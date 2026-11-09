//! What a JavaScript or TypeScript module exports, read from its syntax:
//! each exported name, whether a doc comment documents it, and the modules
//! it re-exports from.

use crate::behavioral::syntax::inspect_program;
use oxc_ast::ast::{
    BindingPattern, Comment, Declaration, ExportDefaultDeclarationKind, ModuleExportName, Program,
    Statement,
};
use oxc_span::SourceType;
use std::collections::HashMap;
use std::rc::Rc;

/// A doc comment counts when its text is at least this long.
pub(crate) const MIN_DOC_CHARS: usize = 20;

/// What one module's syntax says about its exports.
#[derive(Debug, Default)]
pub(crate) struct ModuleFacts {
    /// The module parsed without a syntax error.
    pub parsed: bool,
    /// It has an `import` or `export` declaration.
    pub esm_syntax: bool,
    /// A `.js` file that parses only with JSX, which Node.js can't run.
    pub jsx: bool,
    /// Names it exports from its own declarations, with whether each has a
    /// doc comment.
    pub local: Vec<LocalExport>,
    /// `export { a as b } from "x"`: (exported, imported, specifier), the
    /// specifier shared by the names of one declaration.
    pub named_reexports: Vec<(String, String, Rc<str>)>,
    /// `export * from "x"`.
    pub star_reexports: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct LocalExport {
    pub name: String,
    /// The local declaration it names, which identifies it across names.
    pub local: String,
    pub documented: bool,
}

/// Reads a module's exports. `None` when it doesn't parse at all. A `.js`
/// file is read as JavaScript, and only one that parses solely as JSX is
/// read with JSX.
pub(crate) fn module_facts(path: &str, source: &str) -> Option<ModuleFacts> {
    let source_type = source_type_for(path)?;
    let read = |source_type| {
        inspect_program(source, source_type, |program, complete| {
            let mut facts = collect(program, source);
            facts.parsed = complete;
            facts
        })
    };
    let facts = read(source_type);
    if path.ends_with(".js")
        && facts.as_ref().is_none_or(|facts| !facts.parsed)
        && let Some(mut with_jsx) = read(source_type.with_jsx(true)).filter(|facts| facts.parsed)
    {
        with_jsx.jsx = true;
        return Some(with_jsx);
    }
    facts
}

fn source_type_for(path: &str) -> Option<SourceType> {
    let source_type =
        if path.ends_with(".d.ts") || path.ends_with(".d.mts") || path.ends_with(".d.cts") {
            SourceType::d_ts()
        } else if path.ends_with(".mjs") || path.ends_with(".js") || path.ends_with(".cjs") {
            SourceType::mjs()
        } else if path.ends_with(".jsx") {
            SourceType::jsx()
        } else {
            SourceType::from_path(path).ok()?.with_module(true)
        };
    Some(source_type)
}

/// The text of a doc comment without its delimiters, leading `*`s and
/// extra whitespace.
pub(crate) fn doc_text(raw: &str) -> String {
    let mut text = String::with_capacity(raw.len());
    for line in raw.lines() {
        let line = line.trim().trim_start_matches('*').trim();
        if line.is_empty() {
            continue;
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(line);
    }
    text
}

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// A doc comment's text, worked out once for every name the comment may
/// document.
pub(crate) struct DocSummary {
    long_enough: bool,
    normalized: String,
}

impl DocSummary {
    pub(crate) fn of(text: &str) -> Self {
        Self {
            long_enough: text.chars().count() >= MIN_DOC_CHARS,
            normalized: normalized(text),
        }
    }

    pub(crate) fn documents(&self, name: &str) -> bool {
        self.long_enough && self.normalized != normalized(name)
    }
}

struct DocIndex {
    /// JSDoc comments by the start of the token they lead.
    by_token: HashMap<u32, DocSummary>,
}

impl DocIndex {
    fn new(comments: &[Comment], source: &str) -> Self {
        let by_token = comments
            .iter()
            .filter(|comment| comment.is_leading() && comment.is_jsdoc())
            .filter_map(|comment| {
                let span = comment.content_span();
                source
                    .get(span.start as usize..span.end as usize)
                    .map(|text| (comment.attached_to, DocSummary::of(&doc_text(text))))
            })
            .collect();
        Self { by_token }
    }

    fn documents(&self, starts: &[u32], name: &str) -> bool {
        starts.iter().any(|start| {
            self.by_token
                .get(start)
                .is_some_and(|summary| summary.documents(name))
        })
    }
}

fn export_name(name: &ModuleExportName<'_>) -> String {
    name.name().to_string()
}

fn binding_names(pattern: &BindingPattern<'_>) -> Vec<String> {
    pattern
        .get_binding_identifiers()
        .into_iter()
        .map(|identifier| identifier.name.to_string())
        .collect()
}

/// The names a declaration binds.
fn declared_names(declaration: &Declaration<'_>) -> Vec<String> {
    match declaration {
        Declaration::VariableDeclaration(variables) => variables
            .declarations
            .iter()
            .flat_map(|declarator| binding_names(&declarator.id))
            .collect(),
        Declaration::FunctionDeclaration(function) => {
            function.id.iter().map(|id| id.name.to_string()).collect()
        }
        Declaration::ClassDeclaration(class) => {
            class.id.iter().map(|id| id.name.to_string()).collect()
        }
        Declaration::TSTypeAliasDeclaration(alias) => vec![alias.id.name.to_string()],
        Declaration::TSInterfaceDeclaration(interface) => vec![interface.id.name.to_string()],
        Declaration::TSEnumDeclaration(enumeration) => vec![enumeration.id.name.to_string()],
        Declaration::TSNamespaceDeclaration(namespace) => vec![namespace.id.name.to_string()],
        Declaration::TSImportEqualsDeclaration(import) => vec![import.id.name.to_string()],
        Declaration::TSExternalModuleDeclaration(_) | Declaration::TSGlobalDeclaration(_) => {
            Vec::new()
        }
    }
}

fn declaration_start(declaration: &Declaration<'_>) -> u32 {
    use oxc_span::GetSpan as _;
    declaration.span().start
}

fn collect(program: &Program<'_>, source: &str) -> ModuleFacts {
    use oxc_span::GetSpan as _;
    let docs = DocIndex::new(&program.comments, source);
    let mut facts = ModuleFacts::default();

    // Top-level declarations by name, with whether any of them (overloads,
    // merged interfaces) is documented, for `export { name }`.
    let mut declarations: HashMap<String, bool> = HashMap::new();
    let mut note_declaration = |declaration: &Declaration<'_>, starts: &[u32]| {
        for name in declared_names(declaration) {
            let documented = docs.documents(starts, &name);
            let entry = declarations.entry(name).or_insert(false);
            *entry |= documented;
        }
    };
    for statement in &program.body {
        match statement {
            Statement::ExportDeclaration(export) => {
                note_declaration(
                    &export.declaration,
                    &[export.span.start, declaration_start(&export.declaration)],
                );
            }
            _ => {
                if let Some(declaration) = statement.as_declaration() {
                    note_declaration(declaration, &[declaration_start(declaration)]);
                }
            }
        }
    }

    let mut local = |name: String, target: String, documented: bool| {
        facts.local.push(LocalExport {
            name,
            local: target,
            documented,
        });
    };
    let mut named_reexports = Vec::new();
    let mut star_reexports = Vec::new();
    let mut esm_syntax = false;
    for statement in &program.body {
        match statement {
            Statement::ImportDeclaration(_) => esm_syntax = true,
            Statement::ExportDeclaration(export) => {
                esm_syntax = true;
                for name in declared_names(&export.declaration) {
                    let documented = declarations.get(&name).copied().unwrap_or(false);
                    local(name.clone(), name, documented);
                }
            }
            Statement::ExportNamedDeclaration(export) => {
                esm_syntax = true;
                for specifier in &export.specifiers {
                    let target = export_name(&specifier.local);
                    let documented = declarations.get(&target).copied().unwrap_or(false)
                        || docs.documents(&[specifier.span.start], &target);
                    local(export_name(&specifier.exported), target, documented);
                }
            }
            Statement::ExportFromDeclaration(export) => {
                esm_syntax = true;
                let Some(specifier_source) = export.source.value.as_str().map(Rc::<str>::from)
                else {
                    continue;
                };
                for specifier in &export.specifiers {
                    named_reexports.push((
                        export_name(&specifier.exported),
                        export_name(&specifier.local),
                        Rc::clone(&specifier_source),
                    ));
                }
            }
            Statement::ExportAllDeclaration(export) => {
                esm_syntax = true;
                let Some(specifier_source) = export.source.value.as_str().map(str::to_string)
                else {
                    continue;
                };
                match &export.exported {
                    Some(namespace) => {
                        let name = export_name(namespace);
                        let documented = docs.documents(&[export.span.start], &name);
                        local(name.clone(), format!("* as {name}"), documented);
                    }
                    None => star_reexports.push(specifier_source),
                }
            }
            Statement::ExportDefaultDeclaration(export) => {
                esm_syntax = true;
                let (target, mut starts) = match &export.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => (
                        function.id.as_ref().map(|id| id.name.to_string()),
                        vec![function.span.start],
                    ),
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => (
                        class.id.as_ref().map(|id| id.name.to_string()),
                        vec![class.span.start],
                    ),
                    ExportDefaultDeclarationKind::TSInterfaceDeclaration(interface) => (
                        Some(interface.id.name.to_string()),
                        vec![interface.span.start],
                    ),
                    expression => (
                        expression
                            .as_expression()
                            .and_then(|expression| expression.get_identifier_reference())
                            .map(|identifier| identifier.name.to_string()),
                        vec![expression.span().start],
                    ),
                };
                starts.push(export.span.start);
                let documented = docs.documents(&starts, "default")
                    || target
                        .as_ref()
                        .and_then(|name| declarations.get(name))
                        .copied()
                        .unwrap_or(false);
                local(
                    "default".to_string(),
                    target.unwrap_or_else(|| "default".to_string()),
                    documented,
                );
            }
            Statement::TSExportAssignment(export) => {
                esm_syntax = true;
                let target = export
                    .expression
                    .get_identifier_reference()
                    .map(|identifier| identifier.name.to_string());
                let documented = docs.documents(&[export.span.start], "default")
                    || target
                        .as_ref()
                        .and_then(|name| declarations.get(name))
                        .copied()
                        .unwrap_or(false);
                local(
                    "default".to_string(),
                    target.unwrap_or_else(|| "default".to_string()),
                    documented,
                );
            }
            Statement::TSNamespaceExportDeclaration(_) => {}
            _ => {}
        }
    }
    facts.named_reexports = named_reexports;
    facts.star_reexports = star_reexports;
    facts.esm_syntax = esm_syntax;
    facts
}

/// One import of the package in a README example: the module specifier and
/// the names imported from it. `names` is `None` for a namespace import or
/// a whole-module `require`, which name nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExampleImport {
    pub specifier: String,
    pub names: Option<Vec<String>>,
}

/// The imports of `package` (or a subpath of it) in a README code block.
pub(crate) fn example_imports(code: &str, typescript: bool, package: &str) -> Vec<ExampleImport> {
    let source_type = if typescript {
        SourceType::tsx()
    } else {
        SourceType::mjs().with_jsx(true)
    };
    let names_package = |specifier: &str| {
        specifier == package
            || specifier
                .strip_prefix(package)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    inspect_program(code, source_type, |program, _| {
        let mut imports = Vec::new();
        for statement in &program.body {
            match statement {
                Statement::ImportDeclaration(import) => {
                    let Some(specifier) = import.source.value.as_str().map(str::to_string) else {
                        continue;
                    };
                    if !names_package(&specifier) {
                        continue;
                    }
                    let mut names = Some(Vec::new());
                    for item in import.specifiers.iter().flatten() {
                        use oxc_ast::ast::ImportDeclarationSpecifier as Item;
                        match item {
                            Item::ImportSpecifier(named) => {
                                if let Some(list) = names.as_mut() {
                                    list.push(export_name(&named.imported));
                                }
                            }
                            Item::ImportDefaultSpecifier(_) => {
                                if let Some(list) = names.as_mut() {
                                    list.push("default".to_string());
                                }
                            }
                            Item::ImportNamespaceSpecifier(_) => names = None,
                        }
                    }
                    imports.push(ExampleImport { specifier, names });
                }
                Statement::VariableDeclaration(variables) => {
                    for declarator in &variables.declarations {
                        let Some(specifier) = declarator.init.as_ref().and_then(required_specifier)
                        else {
                            continue;
                        };
                        if !names_package(&specifier) {
                            continue;
                        }
                        let names = match &declarator.id {
                            BindingPattern::ObjectPattern(object) => Some(
                                object
                                    .properties
                                    .iter()
                                    .filter_map(|property| {
                                        property
                                            .key
                                            .static_name()
                                            .and_then(|name| name.as_str().map(str::to_string))
                                    })
                                    .collect(),
                            ),
                            _ => None,
                        };
                        imports.push(ExampleImport { specifier, names });
                    }
                }
                _ => {}
            }
        }
        imports
    })
    .unwrap_or_default()
}

/// The specifier of `require("x")` or `await import("x")`.
fn required_specifier(expression: &oxc_ast::ast::Expression<'_>) -> Option<String> {
    use oxc_ast::ast::{Argument, Expression};
    match expression.without_parentheses() {
        Expression::CallExpression(call) => {
            let callee = call.callee.get_identifier_reference()?;
            if callee.name != "require" {
                return None;
            }
            match call.arguments.first()? {
                Argument::StringLiteral(literal) => literal.value.as_str().map(str::to_string),
                _ => None,
            }
        }
        Expression::AwaitExpression(awaited) => match awaited.argument.without_parentheses() {
            Expression::ImportExpression(import) => match &import.source {
                Expression::StringLiteral(literal) => literal.value.as_str().map(str::to_string),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(path: &str, source: &str) -> ModuleFacts {
        module_facts(path, source).expect("parses")
    }

    fn documented(facts: &ModuleFacts) -> Vec<(&str, bool)> {
        facts
            .local
            .iter()
            .map(|export| (export.name.as_str(), export.documented))
            .collect()
    }

    #[test]
    fn declaration_exports_are_documented_by_the_jsdoc_above_them() {
        let facts = parse(
            "index.d.ts",
            "/** Parses Markdown into sanitized HTML. */\nexport declare function parse(input: string): string;\n/** short */\nexport declare const version: string;\nexport interface Options { gfm: boolean }\n",
        );
        assert!(facts.parsed && facts.esm_syntax);
        assert_eq!(
            documented(&facts),
            [("parse", true), ("version", false), ("Options", false)]
        );
    }

    #[test]
    fn one_long_doc_comment_over_many_bindings_is_read_once() {
        let names: Vec<String> = (0..20_000)
            .map(|index| format!("n{index}: number"))
            .collect();
        let source = format!(
            "/** {} */\nexport declare const {};\n",
            "Describes the value. ".repeat(5_000),
            names.join(", ")
        );
        let facts = parse("index.d.ts", &source);
        assert_eq!(facts.local.len(), 20_000);
        assert!(facts.local.iter().all(|export| export.documented));
    }

    #[test]
    fn a_doc_comment_that_only_repeats_the_name_does_not_count() {
        let facts = parse(
            "index.d.ts",
            "/** createMarkdownRendererInstance */\nexport declare function createMarkdownRendererInstance(): void;\n",
        );
        assert_eq!(
            documented(&facts),
            [("createMarkdownRendererInstance", false)]
        );
        assert!(
            !DocSummary::of("Create markdown-renderer instance")
                .documents("createMarkdownRendererInstance")
        );
    }

    #[test]
    fn local_export_lists_take_the_documentation_of_the_declaration_they_name() {
        let facts = parse(
            "index.mjs",
            "/** Formats a byte count for people to read. */\nfunction formatBytes(n) { return n }\nconst other = 1\nexport { formatBytes as format, other }\n",
        );
        assert_eq!(documented(&facts), [("format", true), ("other", false)]);
        assert_eq!(facts.local[0].local, "formatBytes");
    }

    #[test]
    fn overloads_are_documented_when_any_signature_is() {
        let facts = parse(
            "index.d.ts",
            "/** Reads a value from the store by its key. */\nexport declare function get(key: string): string;\nexport declare function get(key: number): string;\n",
        );
        assert_eq!(documented(&facts), [("get", true), ("get", true)]);
    }

    #[test]
    fn reexports_are_recorded_with_their_specifiers() {
        let facts = parse(
            "index.d.ts",
            "export * from './a.js';\nexport { b as c, type T } from './b';\nexport * as ns from './n';\n",
        );
        assert_eq!(facts.star_reexports, ["./a.js"]);
        let named: Vec<(&str, &str, &str)> = facts
            .named_reexports
            .iter()
            .map(|(exported, local, specifier)| (exported.as_str(), local.as_str(), &**specifier))
            .collect();
        assert_eq!(named, [("c", "b", "./b"), ("T", "T", "./b")]);
        assert_eq!(documented(&facts), [("ns", false)]);
    }

    #[test]
    fn default_exports_are_named_default() {
        let facts = parse(
            "index.d.ts",
            "/** The client that talks to the API server. */\ndeclare class Client {}\nexport default Client;\n",
        );
        assert_eq!(documented(&facts), [("default", true)]);
        let facts = parse(
            "index.d.ts",
            "/** The client that talks to the API server. */\ndeclare class Client {}\nexport = Client;\n",
        );
        assert_eq!(documented(&facts), [("default", true)]);
    }

    #[test]
    fn commonjs_has_no_esm_syntax() {
        let facts = parse("index.js", "module.exports = { a: 1 }\n");
        assert!(facts.parsed && !facts.esm_syntax);
    }

    #[test]
    fn example_imports_cover_named_default_namespace_and_require() {
        let code = "import parse, { render as r } from '@lpm.dev/acme.md'\nimport * as all from '@lpm.dev/acme.md/extra'\nimport other from 'react'\nconst { stringify } = require('@lpm.dev/acme.md')\nconst whole = require('@lpm.dev/acme.md')\n";
        assert_eq!(
            example_imports(code, false, "@lpm.dev/acme.md"),
            [
                ExampleImport {
                    specifier: "@lpm.dev/acme.md".into(),
                    names: Some(vec!["default".into(), "render".into()]),
                },
                ExampleImport {
                    specifier: "@lpm.dev/acme.md/extra".into(),
                    names: None,
                },
                ExampleImport {
                    specifier: "@lpm.dev/acme.md".into(),
                    names: Some(vec!["stringify".into()]),
                },
                ExampleImport {
                    specifier: "@lpm.dev/acme.md".into(),
                    names: None,
                },
            ]
        );
    }

    #[test]
    fn example_imports_ignore_a_package_whose_name_only_starts_alike() {
        assert!(
            example_imports(
                "import x from '@lpm.dev/acme.mdx'",
                false,
                "@lpm.dev/acme.md"
            )
            .is_empty()
        );
    }
}
