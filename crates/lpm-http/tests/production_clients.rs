use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, ExprPath, ImplItemFn, ItemFn, ItemImpl, ItemMod,
    ItemUse, UseTree,
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
                if prefix.first().is_some_and(|root| root == "reqwest") && name.ident == "Client" {
                    self.clients.insert(name.ident.to_string());
                }
            }
            UseTree::Rename(rename) => {
                if prefix.first().is_some_and(|root| root == "reqwest") && rename.ident == "Client"
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
    protected_depth: usize,
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
                .is_some_and(|ty| ty == "Client");
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

fn chain_has_no_follow_policy(expression: &Expr) -> bool {
    match expression {
        Expr::MethodCall(call) => {
            (call.method == "redirect" && call.args.iter().any(is_policy_none))
                || chain_has_no_follow_policy(&call.receiver)
        }
        Expr::Paren(paren) => chain_has_no_follow_policy(&paren.expr),
        Expr::Group(group) => chain_has_no_follow_policy(&group.expr),
        _ => false,
    }
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
        if chain_has_no_follow_policy(&Expr::MethodCall(call.clone())) {
            self.protected_depth += 1;
            self.visit_expr(&call.receiver);
            self.protected_depth -= 1;
            for argument in &call.args {
                self.visit_expr(argument);
            }
        } else {
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if self.protected_depth == 0
            && let Some(constructor) = self.is_reqwest_constructor(call)
        {
            self.violations.push(constructor);
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn production_reqwest_clients_use_shared_or_no_follow_redirect_policy() {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut sources = Vec::new();
    collect_rust_sources(&crates, &mut sources);
    let shared_source = root.join("crates/lpm-http/src");
    let mut violations = Vec::new();

    for path in sources {
        if is_test_source(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if source.contains(".default_headers(") {
            violations.push(format!(
                "{}: default headers can bypass redirect sanitization",
                path.strip_prefix(&root).unwrap_or(&path).display()
            ));
        }
        if path.starts_with(&shared_source) {
            continue;
        }
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        let mut aliases = ReqwestAliases::default();
        aliases.visit_file(&syntax);
        let mut audit = ClientConstructorAudit {
            aliases: &aliases.clients,
            protected_depth: 0,
            violations: Vec::new(),
        };
        audit.visit_file(&syntax);
        for constructor in audit.violations {
            violations.push(format!(
                "{}: unprotected {constructor}",
                path.strip_prefix(&root).unwrap_or(&path).display()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "production reqwest constructors must use lpm-http or explicitly apply Policy::none(), and must not configure default headers:\n{}",
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
        "lpm_http::client_builder()",
    );
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
        "RegistryClient::build_http_client_with_tls_and_identity(",
    );

    let registry_api = read_workspace_source("crates/lpm-registry/src/client/api.rs");
    assert_body_contains(
        &registry_api,
        "pub async fn publish_package(",
        "lpm_http::client_builder()",
    );

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
    assert_body_contains(
        &remote_cache,
        "fn blocking_http_client()",
        "lpm_http::blocking_client_builder()",
    );
}
