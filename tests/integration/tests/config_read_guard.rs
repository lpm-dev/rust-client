use std::collections::HashSet;
use std::path::{Path, PathBuf};

use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, ExprPath, ImplItemFn, ItemFn, ItemMod, ItemUse,
    UseTree,
};

const AUDITED_CONFIGURATION_LOADERS: &[&str] = &[
    "crates/lpm-auth/src/lib.rs",
    "crates/lpm-auth/src/session.rs",
    "crates/lpm-cert/src/ca.rs",
    "crates/lpm-cert/src/cert.rs",
    "crates/lpm-cert/src/framework.rs",
    "crates/lpm-cert/src/lib.rs",
    "crates/lpm-cert/src/projects.rs",
    "crates/lpm-cert/src/rotate.rs",
    "crates/lpm-cert/src/trust.rs",
    "crates/lpm-cli/src/added_sources_state.rs",
    "crates/lpm-cli/src/build_state.rs",
    "crates/lpm-cli/src/capability.rs",
    "crates/lpm-cli/src/cli/dispatch.rs",
    "crates/lpm-cli/src/commands/add/dependencies.rs",
    "crates/lpm-cli/src/commands/add/project.rs",
    "crates/lpm-cli/src/commands/add/source.rs",
    "crates/lpm-cli/src/commands/approve_scripts/display.rs",
    "crates/lpm-cli/src/commands/approve_scripts/project.rs",
    "crates/lpm-cli/src/commands/audit/cache.rs",
    "crates/lpm-cli/src/commands/audit/discovery.rs",
    "crates/lpm-cli/src/commands/audit/fix.rs",
    "crates/lpm-cli/src/commands/config/io.rs",
    "crates/lpm-cli/src/commands/deploy/file_select.rs",
    "crates/lpm-cli/src/commands/deploy/manifest_rewrite.rs",
    "crates/lpm-cli/src/commands/deploy/paths.rs",
    "crates/lpm-cli/src/commands/dev.rs",
    "crates/lpm-cli/src/commands/doctor/config_file.rs",
    "crates/lpm-cli/src/commands/doctor/local_sources.rs",
    "crates/lpm-cli/src/commands/doctor/lockfile.rs",
    "crates/lpm-cli/src/commands/doctor/mod.rs",
    "crates/lpm-cli/src/commands/doctor/script_policy.rs",
    "crates/lpm-cli/src/commands/env/inventory.rs",
    "crates/lpm-cli/src/commands/env/schema.rs",
    "crates/lpm-cli/src/commands/global_util.rs",
    "crates/lpm-cli/src/commands/graph.rs",
    "crates/lpm-cli/src/commands/init.rs",
    "crates/lpm-cli/src/commands/install/gitignore.rs",
    "crates/lpm-cli/src/commands/install/lifecycle.rs",
    "crates/lpm-cli/src/commands/install/manifest.rs",
    "crates/lpm-cli/src/commands/install/source_resolution.rs",
    "crates/lpm-cli/src/commands/install/state.rs",
    "crates/lpm-cli/src/commands/install/workspace.rs",
    "crates/lpm-cli/src/commands/manifest_metadata.rs",
    "crates/lpm-cli/src/commands/mcp.rs",
    "crates/lpm-cli/src/commands/migrate.rs",
    "crates/lpm-cli/src/commands/npmrc.rs",
    "crates/lpm-cli/src/commands/patch.rs",
    "crates/lpm-cli/src/commands/proxy/mod.rs",
    "crates/lpm-cli/src/commands/proxy/proxy_service.rs",
    "crates/lpm-cli/src/commands/publish/orchestrator.rs",
    "crates/lpm-cli/src/commands/publish/prepare.rs",
    "crates/lpm-cli/src/commands/publish/provenance.rs",
    "crates/lpm-cli/src/commands/publish/skills.rs",
    "crates/lpm-cli/src/commands/publish/upload_lpm.rs",
    "crates/lpm-cli/src/commands/query.rs",
    "crates/lpm-cli/src/commands/rebuild/scripts.rs",
    "crates/lpm-cli/src/commands/rebuild/trust.rs",
    "crates/lpm-cli/src/commands/run/cache.rs",
    "crates/lpm-cli/src/commands/run/single.rs",
    "crates/lpm-cli/src/commands/skills/managed.rs",
    "crates/lpm-cli/src/commands/skills/inventory.rs",
    "crates/lpm-cli/src/commands/skills/package.rs",
    "crates/lpm-cli/src/commands/store.rs",
    "crates/lpm-cli/src/commands/swift_registry.rs",
    "crates/lpm-cli/src/commands/tidy.rs",
    "crates/lpm-cli/src/commands/trust.rs",
    "crates/lpm-cli/src/commands/uninstall.rs",
    "crates/lpm-cli/src/commands/upgrade.rs",
    "crates/lpm-cli/src/commands/use.rs",
    "crates/lpm-cli/src/constraints.rs",
    "crates/lpm-cli/src/install_state.rs",
    "crates/lpm-cli/src/intelligence.rs",
    "crates/lpm-cli/src/manifest_tx.rs",
    "crates/lpm-cli/src/release_age_config.rs",
    "crates/lpm-cli/src/release_lookup.rs",
    "crates/lpm-cli/src/release_plan.rs",
    "crates/lpm-cli/src/sandbox_config.rs",
    "crates/lpm-cli/src/save_config.rs",
    "crates/lpm-cli/src/script_policy_config.rs",
    "crates/lpm-cli/src/security_approval/managed_policy.rs",
    "crates/lpm-cli/src/security_approval/project_state.rs",
    "crates/lpm-cli/src/security_approval/signed_store.rs",
    "crates/lpm-cli/src/trust_snapshot.rs",
    "crates/lpm-cli/src/typosquat_guard.rs",
    "crates/lpm-cli/src/workspace_concurrency_config.rs",
    "crates/lpm-cli/src/workspace_filter_config.rs",
    "crates/lpm-linker/src/v1_hoisted.rs",
    "crates/lpm-linker/src/v1_isolated.rs",
    "crates/lpm-linker/src/v2.rs",
    "crates/lpm-linker/src/v2/bin_shims.rs",
    "crates/lpm-linker/src/v2/compat_island.rs",
    "crates/lpm-migrate/src/backup.rs",
    "crates/lpm-migrate/src/lib.rs",
    "crates/lpm-migrate/src/validate.rs",
    "crates/lpm-proxy/src/tls.rs",
    "crates/lpm-registry/src/client/cache.rs",
    "crates/lpm-registry/src/client/config.rs",
    "crates/lpm-registry/src/client/http.rs",
    "crates/lpm-registry/src/npmrc/discovery.rs",
    "crates/lpm-registry/src/npmrc/parse.rs",
    "crates/lpm-registry/src/tls_identity.rs",
    "crates/lpm-runner/src/bin_path.rs",
    "crates/lpm-runner/src/dotenv.rs",
    "crates/lpm-runner/src/local_domains.rs",
    "crates/lpm-runner/src/lpm_json.rs",
    "crates/lpm-runner/src/ports.rs",
    "crates/lpm-runner/src/script.rs",
    "crates/lpm-runtime/src/bun.rs",
    "crates/lpm-runtime/src/detect.rs",
    "crates/lpm-runtime/src/node.rs",
    "crates/lpm-sandbox/src/config.rs",
    "crates/lpm-security/src/behavioral/mod.rs",
    "crates/lpm-security/src/script_hash.rs",
    "crates/lpm-tunnel/src/client.rs",
    "crates/lpm-tunnel/src/relay.rs",
    "crates/lpm-vault/src/crypto.rs",
    "crates/lpm-vault/src/fallback.rs",
    "crates/lpm-vault/src/lib.rs",
    "crates/lpm-vault/src/sync/public_key.rs",
    "crates/lpm-vault/src/vault_id.rs",
    "crates/lpm-workspace/src/catalog.rs",
    "crates/lpm-workspace/src/discovery.rs",
    "crates/lpm-workspace/src/package_json.rs",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical workspace root")
}

fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if attr.path().is_ident("test") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return false;
        }
        match &attr.meta {
            syn::Meta::List(list) => list.tokens.to_string() == "test",
            _ => false,
        }
    })
}

struct RawReadAudit {
    relative: &'static str,
    fs_aliases: HashSet<String>,
    current_function: Option<String>,
    violations: Vec<String>,
}

impl RawReadAudit {
    fn is_raw_fs_call(&self, call: &ExprCall) -> Option<String> {
        let Expr::Path(ExprPath { path, .. }) = call.func.as_ref() else {
            return None;
        };
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let operation = segments.last()?;
        if !matches!(operation.as_str(), "read" | "read_to_string") {
            return None;
        }
        let qualifier = segments.get(segments.len().checked_sub(2)?)?;
        (self.fs_aliases.contains(qualifier) || qualifier == "fs").then(|| segments.join("::"))
    }

    fn is_reviewed_exception(&self, operation: &str) -> bool {
        let function = self.current_function.as_deref().unwrap_or("");
        matches!(
            (self.relative, function, operation),
            (
                "crates/lpm-cli/src/build_state.rs",
                "read_referenced_file",
                "std::fs::read"
            ) | (
                "crates/lpm-cli/src/commands/audit/discovery.rs",
                "detect_npm_lockfile_version",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/audit/discovery.rs",
                "detect_pnpm_lockfile_version",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/audit/discovery.rs",
                "parse_npm_package_paths",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/init.rs",
                "ensure_agents_snippet",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/install/source_resolution.rs",
                "read_local_tarball_bounded",
                ".read_to_end"
            ) | (
                "crates/lpm-cli/src/commands/install/state.rs",
                "write_post_install_hash",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/install/state.rs",
                "dependency_engine_freshness_key_for_state",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/tidy.rs",
                "read",
                "std::fs::read"
            ) | (
                "crates/lpm-cli/src/commands/upgrade.rs",
                "read_optional_file",
                "std::fs::read"
            ) | (
                "crates/lpm-cli/src/intelligence.rs",
                "scan_file",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/manifest_tx.rs",
                "snapshot_optional_paths",
                "std::fs::read"
            ) | (
                "crates/lpm-cli/src/commands/skills/managed.rs",
                "print_external_view",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/commands/skills/managed.rs",
                "collect_skill_text_files",
                "std::fs::read"
            ) | (
                "crates/lpm-cli/src/commands/skills/package.rs",
                "materialized_directory_complete",
                "std::fs::read"
            ) | (
                "crates/lpm-cli/src/install_state.rs",
                "invalid_linker_state",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/install_state.rs",
                "invalid_integrity_state",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/install_state.rs",
                "check_install_state_with_linker_integrity_and_dependency_engine",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-cli/src/security_approval/signed_store.rs",
                "audit_log_unverified_reason",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-runner/src/ports.rs",
                "parse_proc_net_tcp_file",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-runner/src/ports.rs",
                "read_linux_process_info",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-runner/src/ports.rs",
                "read_linux_process_info",
                "std::fs::read"
            ) | (
                "crates/lpm-runner/src/ports.rs",
                "read_linux_process_uptime",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-runner/src/ports.rs",
                "linux_system_uptime_secs",
                "std::fs::read_to_string"
            ) | (
                "crates/lpm-security/src/behavioral/mod.rs",
                "analyze_single_file",
                "std::fs::read"
            ) | (
                "crates/lpm-security/src/behavioral/mod.rs",
                "read_file_chunk",
                ".read_to_end"
            ) | (
                "crates/lpm-security/src/script_hash.rs",
                "hash_delegate_graph",
                "std::fs::read"
            )
        )
    }
}

impl<'ast> Visit<'ast> for RawReadAudit {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_only(&item.attrs) {
            let previous = self.current_function.replace(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.current_function = previous;
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        if !is_test_only(&item.attrs) {
            let previous = self.current_function.replace(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
            self.current_function = previous;
        }
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some(operation) = self.is_raw_fs_call(call)
            && !self.is_reviewed_exception(&operation)
        {
            self.violations.push(format!(
                "{}: {operation}",
                self.current_function.as_deref().unwrap_or("<module>")
            ));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if matches!(
            call.method.to_string().as_str(),
            "read_to_string" | "read_to_end"
        ) {
            let operation = format!(".{}", call.method);
            if !self.is_reviewed_exception(&operation) {
                self.violations.push(format!(
                    "{}: {operation}",
                    self.current_function.as_deref().unwrap_or("<module>")
                ));
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct FsAliasCollector {
    aliases: HashSet<String>,
}

impl FsAliasCollector {
    fn collect_use_tree(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.collect_use_tree(&path.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(name) => {
                if matches!(prefix.first().map(String::as_str), Some("std" | "tokio"))
                    && name.ident == "fs"
                {
                    self.aliases.insert("fs".to_string());
                }
            }
            UseTree::Rename(rename) => {
                if matches!(prefix.first().map(String::as_str), Some("std" | "tokio"))
                    && rename.ident == "fs"
                {
                    self.aliases.insert(rename.rename.to_string());
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

impl<'ast> Visit<'ast> for FsAliasCollector {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.collect_use_tree(&item.tree, &mut Vec::new());
    }
}

#[test]
fn audited_configuration_loaders_use_bounded_file_reads() {
    let root = workspace_root();
    let mut violations = Vec::new();

    for relative in AUDITED_CONFIGURATION_LOADERS {
        let path = root.join(relative);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        let mut aliases = FsAliasCollector::default();
        aliases.visit_file(&syntax);
        aliases.aliases.insert("fs".to_string());
        let mut audit = RawReadAudit {
            relative,
            fs_aliases: aliases.aliases,
            current_function: None,
            violations: Vec::new(),
        };
        audit.visit_file(&syntax);
        for operation in audit.violations {
            violations.push(format!("{relative}: {operation}"));
        }
    }

    assert!(
        violations.is_empty(),
        "audited configuration loaders must use lpm_common bounded-read helpers:\n{}",
        violations.join("\n")
    );
}
