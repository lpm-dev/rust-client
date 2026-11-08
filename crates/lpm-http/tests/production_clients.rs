use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprCall, ExprLit, ExprMethodCall, ExprPath, ImplItemFn, Item, ItemFn,
    ItemImpl, ItemMod, ItemUse, Lit, UseTree,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical workspace root")
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("read directory entry").path())
        .collect::<Vec<_>>();
    entries.sort_unstable();

    for path in entries {
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn is_test_source(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "tests.rs")
        || path
            .components()
            .any(|component| component.as_os_str() == "tests")
}

fn lexically_normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            other => normal.push(other),
        }
    }
    normal
}

fn path_attribute(attribute: &Attribute) -> Option<String> {
    let syn::Meta::NameValue(value) = &attribute.meta else {
        return None;
    };
    if !value.path.is_ident("path") {
        return None;
    }
    let Expr::Lit(ExprLit {
        lit: Lit::Str(path),
        ..
    }) = &value.value
    else {
        return None;
    };
    Some(path.value())
}

/// The files `path` declares as modules with `mod name;`, each with whether
/// the declaration is compiled only for tests.
fn declared_module_files(path: &Path, syntax: &syn::File) -> Vec<(PathBuf, bool)> {
    let directory = path.parent().expect("source files have a directory");
    let owns_directory = path
        .file_name()
        .is_some_and(|name| name == "lib.rs" || name == "main.rs" || name == "mod.rs");
    let child_directory = if owns_directory {
        directory.to_path_buf()
    } else {
        directory.join(path.file_stem().expect("source files have a stem"))
    };
    let mut files = Vec::new();
    for item in &syntax.items {
        let Item::Mod(module) = item else {
            continue;
        };
        if module.content.is_some() {
            continue;
        }
        let test_only = is_test_only(&module.attrs);
        if let Some(explicit) = module.attrs.iter().find_map(path_attribute) {
            files.push((lexically_normal(&directory.join(explicit)), test_only));
        } else {
            let name = module.ident.to_string();
            files.push((child_directory.join(format!("{name}.rs")), test_only));
            files.push((child_directory.join(name).join("mod.rs"), test_only));
        }
    }
    files
}

/// Source files compiled only for tests: those a `#[cfg(test)]` module
/// declaration includes, and the modules they declare in turn.
fn test_module_files(parsed: &[(PathBuf, String, syn::File)]) -> HashSet<PathBuf> {
    let declared = parsed
        .iter()
        .map(|(path, _, syntax)| (path.as_path(), declared_module_files(path, syntax)))
        .collect::<HashMap<_, _>>();
    let mut pending = declared
        .values()
        .flatten()
        .filter(|(_, test_only)| *test_only)
        .map(|(file, _)| file.clone())
        .collect::<Vec<_>>();
    let mut test_files = HashSet::new();
    while let Some(file) = pending.pop() {
        if let Some(children) = declared.get(file.as_path())
            && !test_files.contains(&file)
        {
            pending.extend(children.iter().map(|(child, _)| child.clone()));
        }
        test_files.insert(file);
    }
    test_files
}

fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr.path();
        if path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
        {
            return true;
        }
        if !path.is_ident("cfg") {
            return false;
        }
        match &attr.meta {
            syn::Meta::List(list) => list.tokens.to_string() == "test",
            _ => false,
        }
    })
}

fn is_client_type(name: &str) -> bool {
    matches!(name, "Client" | "ClientBuilder")
}

#[derive(Default)]
struct ReqwestAliases {
    clients: HashSet<String>,
}

impl ReqwestAliases {
    fn collect_use_tree(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.collect_use_tree(&path.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(name) => {
                if prefix.first().is_some_and(|root| root == "reqwest")
                    && is_client_type(&name.ident.to_string())
                {
                    self.clients.insert(name.ident.to_string());
                }
            }
            UseTree::Rename(rename) => {
                if prefix.first().is_some_and(|root| root == "reqwest")
                    && is_client_type(&rename.ident.to_string())
                {
                    self.clients.insert(rename.rename.to_string());
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use_tree(item, prefix);
                }
            }
            UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for ReqwestAliases {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.collect_use_tree(&item.tree, &mut Vec::new());
    }
}

struct ClientConstructorAudit<'a> {
    aliases: &'a HashSet<String>,
    violations: Vec<String>,
}

impl ClientConstructorAudit<'_> {
    fn is_reqwest_constructor(&self, call: &ExprCall) -> Option<String> {
        let Expr::Path(ExprPath { path, .. }) = call.func.as_ref() else {
            return None;
        };
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if segments == ["reqwest", "get"] || segments == ["reqwest", "blocking", "get"] {
            return Some(segments.join("::"));
        }
        let constructor = segments.last()?;
        if !matches!(constructor.as_str(), "builder" | "new" | "default") {
            return None;
        }

        let is_fully_qualified = segments.first().is_some_and(|root| root == "reqwest")
            && segments
                .get(segments.len().saturating_sub(2))
                .is_some_and(|ty| is_client_type(ty));
        let is_imported = segments.len() == 2
            && self
                .aliases
                .contains(segments.first().expect("two path segments"));
        (is_fully_qualified || is_imported).then(|| segments.join("::"))
    }

    fn chain_starts_with_http_builder(&self, expression: &Expr) -> bool {
        match expression {
            Expr::Call(call) => {
                if self
                    .is_reqwest_constructor(call)
                    .is_some_and(|constructor| constructor.ends_with("::builder"))
                {
                    return true;
                }
                let Expr::Path(path) = call.func.as_ref() else {
                    return false;
                };
                let segments = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>();
                segments.first().is_some_and(|root| root == "lpm_http")
                    && segments.last().is_some_and(|function| {
                        matches!(
                            function.as_str(),
                            "client_builder"
                                | "client_builder_with_redirect_limit"
                                | "client_builder_trusting_only"
                                | "blocking_client_builder"
                        )
                    })
            }
            Expr::MethodCall(call) => self.chain_starts_with_http_builder(&call.receiver),
            Expr::Paren(paren) => self.chain_starts_with_http_builder(&paren.expr),
            Expr::Group(group) => self.chain_starts_with_http_builder(&group.expr),
            _ => false,
        }
    }
}

fn is_policy_none(expression: &Expr) -> bool {
    let Expr::Call(call) = expression else {
        return false;
    };
    let Expr::Path(path) = call.func.as_ref() else {
        return false;
    };
    let mut segments = path.path.segments.iter().rev();
    segments
        .next()
        .is_some_and(|segment| segment.ident == "none")
        && segments
            .next()
            .is_some_and(|segment| segment.ident.to_string().ends_with("Policy"))
}

impl<'ast> Visit<'ast> for ClientConstructorAudit<'_> {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_item_impl(self, item);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "redirect"
            && self.chain_starts_with_http_builder(&call.receiver)
            && !call.args.iter().any(is_policy_none)
        {
            self.violations
                .push("redirect override without Policy::none".into());
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some(constructor) = self.is_reqwest_constructor(call) {
            self.violations.push(constructor);
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn production_reqwest_clients_come_from_lpm_http() {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut sources = Vec::new();
    collect_rust_sources(&crates, &mut sources);
    let shared_source = root.join("crates/lpm-http/src");
    let mut violations = Vec::new();
    let parsed = sources
        .into_iter()
        .filter(|path| !is_test_source(path))
        .map(|path| {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let syntax = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
            (path, source, syntax)
        })
        .collect::<Vec<_>>();
    let test_modules = test_module_files(&parsed);

    for (path, source, syntax) in &parsed {
        if test_modules.contains(path) {
            continue;
        }
        if source.contains(".default_headers(") {
            violations.push(format!(
                "{}: default headers can bypass redirect sanitization",
                path.strip_prefix(&root).unwrap_or(path).display()
            ));
        }
        if path.starts_with(&shared_source) {
            continue;
        }
        let mut aliases = ReqwestAliases::default();
        aliases.visit_file(syntax);
        let mut audit = ClientConstructorAudit {
            aliases: &aliases.clients,
            violations: Vec::new(),
        };
        audit.visit_file(syntax);
        for constructor in audit.violations {
            violations.push(format!(
                "{}: raw {constructor}",
                path.strip_prefix(&root).unwrap_or(path).display()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "production reqwest clients must come from lpm-http, which applies the redirect policy and the trusted roots; a redirect override must be Policy::none(), and default headers are not allowed:\n{}",
        violations.join("\n")
    );
}

fn read_workspace_source(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn function_body<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker {marker}"));
    let open = source[start..].find('{').map_or_else(
        || panic!("missing body for {marker}"),
        |offset| start + offset,
    );
    let mut depth = 0_usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for {marker}");
}

fn assert_body_contains(source: &str, marker: &str, expected: &str) {
    let body = function_body(source, marker);
    assert!(body.contains(expected), "{marker} must contain {expected}");
}

#[test]
fn security_sensitive_client_paths_keep_shared_builders() {
    let registry_config = read_workspace_source("crates/lpm-registry/src/client/config.rs");
    assert_body_contains(
        &registry_config,
        "fn build_http_client_with_tls_identity_and_transport(",
        "build_http_client_with_prepared_tls_identity_and_transport(",
    );
    assert_body_contains(
        &registry_config,
        "fn build_http_client_with_prepared_tls_identity_and_transport(",
        ".client_builder()",
    );
    for builder in [
        "lpm_http::client_builder()",
        "lpm_http::client_builder_trusting_only(",
    ] {
        assert_body_contains(&registry_config, "fn client_builder(&self)", builder);
    }
    assert_body_contains(
        &registry_config,
        "fn build_http_client_with_tls_and_identity(",
        "build_http_client_with_tls_identity_and_transport(",
    );
    assert_body_contains(
        &registry_config,
        "fn build_worker_metadata_http3_client_with_tls(",
        "build_http_client_with_tls_identity_and_transport(",
    );

    let registry_http = read_workspace_source("crates/lpm-registry/src/client/http.rs");
    assert_body_contains(
        &registry_http,
        "fn build_per_origin_http_client(",
        "RegistryClient::build_http_client_set_with_tls_and_identity(",
    );

    let registry_api = read_workspace_source("crates/lpm-registry/src/client/api.rs");
    assert_body_contains(
        &registry_api,
        "async fn send_publish(",
        "self.http.for_url_no_build(&url)",
    );
    for publish in [
        "pub async fn publish_package(",
        "pub async fn publish_approved_package(",
    ] {
        assert_body_contains(&registry_api, publish, "self.send_publish(");
    }

    let vault = read_workspace_source("crates/lpm-vault/src/sync/http.rs");
    assert_body_contains(
        &vault,
        "fn sync_http_client_builder(",
        "lpm_http::client_builder()",
    );

    let platform = read_workspace_source("crates/lpm-cli/src/commands/env/platform/mod.rs");
    assert_body_contains(
        &platform,
        "fn new(token: String, config: VercelConnectionConfig)",
        "lpm_http::client_builder_with_redirect_limit(5)",
    );
    let coolify = read_workspace_source("crates/lpm-cli/src/commands/env/platform/coolify.rs");
    assert_body_contains(&coolify, "pub(super) fn new(", "lpm_http::client_builder()");

    let remote_cache = read_workspace_source("crates/lpm-cli/src/commands/remote_cache.rs");
    for builder in ["fn build_lookup_client()", "fn build_http_client()"] {
        assert_body_contains(&remote_cache, builder, "lpm_http::client_builder()");
    }
}
