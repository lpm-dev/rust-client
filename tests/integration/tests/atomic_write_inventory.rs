use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

#[derive(Default)]
struct RawAtomicOperations {
    writes: Vec<&'static str>,
    replacements: Vec<&'static str>,
}

impl<'ast> Visit<'ast> for RawAtomicOperations {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = expression.func.as_ref() {
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|part| part.ident.to_string())
                .collect();
            match segments.last().map(String::as_str) {
                Some("write") if segments.iter().any(|part| part == "fs") => {
                    self.writes.push("fs::write");
                }
                Some("create") if segments.iter().any(|part| part == "File") => {
                    self.writes.push("File::create");
                }
                Some("to_writer") => self.writes.push("serde to_writer"),
                Some("rename") if segments.iter().any(|part| part == "fs") => {
                    self.replacements.push("fs::rename");
                }
                Some("MoveFileExW") => self.replacements.push("MoveFileExW"),
                _ => {}
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        match expression.method.to_string().as_str() {
            "write_all" | "write_fmt" => self.writes.push("Write method"),
            "create" | "truncate" if boolean_argument(expression, true) => {
                self.writes.push("OpenOptions write configuration");
            }
            "persist" | "persist_noclobber" => self.replacements.push("tempfile persist"),
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, expression);
    }

    fn visit_item_fn(&mut self, _function: &'ast syn::ItemFn) {}

    fn visit_impl_item_fn(&mut self, _function: &'ast syn::ImplItemFn) {}
}

fn boolean_argument(expression: &syn::ExprMethodCall, expected: bool) -> bool {
    matches!(
        expression.args.first(),
        Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Bool(value),
            ..
        })) if value.value == expected
    )
}

struct ProductionFunctionVisitor<'a> {
    relative_path: &'a Path,
    findings: Vec<String>,
    reviewed: Vec<String>,
    in_test_module: bool,
}

impl<'a> ProductionFunctionVisitor<'a> {
    fn inspect(&mut self, name: &syn::Ident, block: &syn::Block, attributes: &[syn::Attribute]) {
        if self.in_test_module || attributes_are_test_only(attributes) {
            return;
        }

        let mut operations = RawAtomicOperations::default();
        operations.visit_block(block);
        if operations.replacements.is_empty() {
            return;
        }

        let key = format!("{}::{name}", self.relative_path.display());
        if reviewed_raw_atomic_writer(&key) {
            self.reviewed.push(key);
            return;
        }
        operations.writes.sort_unstable();
        operations.writes.dedup();
        operations.replacements.sort_unstable();
        operations.replacements.dedup();
        self.findings.push(format!(
            "{key}: writes [{}], replacements [{}]",
            operations.writes.join(", "),
            operations.replacements.join(", ")
        ));
    }
}

impl<'ast> Visit<'ast> for ProductionFunctionVisitor<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let was_in_test_module = self.in_test_module;
        self.in_test_module |= attributes_are_test_only(&module.attrs);
        if let Some((_, items)) = &module.content {
            for item in items {
                self.visit_item(item);
            }
        }
        self.in_test_module = was_in_test_module;
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.inspect(&function.sig.ident, &function.block, &function.attrs);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        self.inspect(&function.sig.ident, &function.block, &function.attrs);
    }
}

fn attributes_are_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg")
                && match &attribute.meta {
                    syn::Meta::List(list) => syn::parse2::<syn::Meta>(list.tokens.clone())
                        .is_ok_and(|predicate| cfg_predicate_requires_test(&predicate)),
                    _ => false,
                })
    })
}

fn cfg_predicate_requires_test(predicate: &syn::Meta) -> bool {
    match predicate {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|predicates| predicates.iter().any(cfg_predicate_requires_test)),
        syn::Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|predicates| {
                !predicates.is_empty() && predicates.iter().all(cfg_predicate_requires_test)
            }),
        syn::Meta::List(_) | syn::Meta::NameValue(_) => false,
    }
}

fn reviewed_raw_atomic_writer(key: &str) -> bool {
    REVIEWED_RAW_ATOMIC_WRITERS
        .iter()
        .any(|(reviewed, _reason)| *reviewed == key)
}

const REVIEWED_RAW_ATOMIC_WRITERS: &[(&str, &str)] = &[
    (
        "crates/lpm-audit-corpus/src/layers/l4.rs::enrich_advisor_in_place",
        "the persist method belongs to L4Cache and delegates to the shared secure writer",
    ),
    (
        "crates/lpm-cli/src/commands/remove.rs::move_path",
        "moves preflight-validated project-owned entries into an exclusively created quarantine and records each move for rollback",
    ),
    (
        "crates/lpm-cli/src/commands/remove.rs::restore_file",
        "moves an integrity-verified managed backup into its validated destination while retaining the open file and rollback entry",
    ),
    (
        "crates/lpm-cli/src/commands/remove.rs::drop",
        "restores paths recorded by the source-removal transaction after an incomplete mutation",
    ),
    (
        "crates/lpm-cli/src/commands/install/workspace_project_state.rs::move_to_backup",
        "moves project-owned install state into an exclusively created rollback directory before replacement",
    ),
    (
        "crates/lpm-cli/src/commands/install/workspace_project_state.rs::rollback_inner",
        "restores complete project-owned paths from the transaction's exclusively created rollback directory",
    ),
    (
        "crates/lpm-cli/src/commands/npm_stage.rs::download_staged_package",
        "streams into an exclusively created same-directory NamedTempFile, syncs and validates it, then publishes with persist_noclobber",
    ),
    (
        "crates/lpm-cli/src/commands/rebuild/build_cache/toolchain_snapshot.rs::write_snapshot",
        "NamedTempFile exclusively creates a randomized sibling before persist",
    ),
    (
        "crates/lpm-runner/src/dev_session.rs::commit_reversible_with_directory_sync",
        "publishes a randomized same-directory staging file installed by the shared secure writer and retains the prior record for rollback",
    ),
    (
        "crates/lpm-cli/src/commands/run/single.rs::recover_managed_runtime",
        "restores a complete verified MCP runtime directory while holding the MCP cache lock",
    ),
    (
        "crates/lpm-cli/src/commands/run/single.rs::replace_managed_runtime",
        "swaps complete MCP runtime directories with rollback while holding the MCP cache lock",
    ),
    (
        "crates/lpm-cli/src/commands/self_update.rs::install_staged_binary",
        "receives an exclusively created same-directory NamedTempFile; Windows needs a custom running-binary swap",
    ),
    (
        "crates/lpm-cli/src/commands/self_update.rs::install_staged_macos_bundle",
        "swaps a validated app bundle and launchers from an exclusively created same-directory TempDir with rollback",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::write_state",
        "NamedTempFile exclusively creates a randomized sibling before persist",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::commit_staged_install",
        "publishes an exclusively created skill directory transaction",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::rollback_staged_install",
        "restores directories owned by the skill transaction",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::stage_owned_removal",
        "moves an owned skill directory into the transaction for rollback",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::commit_target_stages",
        "publishes exclusively created skill target directories",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::rollback_target_stages",
        "restores directories owned by the skill target transaction",
    ),
    (
        "crates/lpm-cli/src/commands/skills/managed.rs::rollback_removed_targets",
        "restores directories owned by the skill removal transaction",
    ),
    (
        "crates/lpm-cli/src/commands/skills/package.rs::materialize",
        "writes are inside an exclusively created temporary directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-cli/src/security_approval/signed_store.rs::quarantine_security_state_file",
        "moves an existing unverified state file to a fresh quarantine name without writing a temporary leaf",
    ),
    (
        "crates/lpm-cli/src/triage_advisor_session.rs::classify_amber",
        "the persist method belongs to L4Cache and delegates to the shared secure writer",
    ),
    (
        "crates/lpm-common/src/atomic_write.rs::replace_file",
        "this is the platform replacement boundary of the shared secure writer",
    ),
    (
        "crates/lpm-linker/src/v2/compat_island.rs::ensure_store_compat_island",
        "writes are inside a newly created staging directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-linker/src/v2/compat_island.rs::ensure_compatibility_package_copy",
        "publishes a package directory staged by the compatibility-island transaction",
    ),
    (
        "crates/lpm-plugin/src/engine.rs::install_under_lock_at",
        "publishes an engine directory created under the engine installation lock",
    ),
    (
        "crates/lpm-runner/src/dlx.rs::migrate_legacy_dlx_cache",
        "moves existing package directories during a cache-layout migration",
    ),
    (
        "crates/lpm-runtime/src/download.rs::install_bun_with_report",
        "moves the extracted Bun executable within a private staging directory",
    ),
    (
        "crates/lpm-runtime/src/download.rs::rename_with_fallback",
        "performs a cross-filesystem move with copy fallback rather than an atomic file rewrite",
    ),
    (
        "crates/lpm-store/src/extraction.rs::store_at_dir",
        "writes are inside an extraction directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-store/src/extraction.rs::store_from_file_at_timed",
        "writes are inside an extraction directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-store/src/extraction.rs::stream_and_store_package",
        "writes are inside an extraction directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-store/src/v2/build_cache.rs::publish_build_artifact",
        "writes are inside a build-artifact directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-store/src/v2/build_cache.rs::replace_with_staged_tree",
        "swaps complete package directory trees with rollback",
    ),
    (
        "crates/lpm-store/src/v2/integrity.rs::claim_unusable_object_dir",
        "moves an object directory to a random removal claim before deletion",
    ),
    (
        "crates/lpm-store/src/v2/integrity.rs::finish_object_rename_after_collision",
        "publishes or discards a complete object directory after a concurrent directory transaction",
    ),
    (
        "crates/lpm-store/src/v2/local_source.rs::replace_local_source_object",
        "swaps complete local-source object directories with rollback",
    ),
    (
        "crates/lpm-store/src/v2/local_source.rs::finish_local_source_object_rename",
        "publishes or discards a complete local-source object directory after a concurrent transaction",
    ),
    (
        "crates/lpm-store/src/v2/store.rs::publish_staged_object",
        "writes are inside an object staging directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-store/src/v2/store.rs::populate_object_from_existing_tree",
        "writes are inside an object staging directory that is published as a directory transaction",
    ),
    (
        "crates/lpm-store/src/v2/store.rs::populate_link_entry_inner",
        "publishes a complete link-entry directory after staging",
    ),
    (
        "crates/lpm-store/src/v3/cas.rs::quarantine_entry",
        "moves a corrupt CAS entry to a randomized quarantine path without rewriting its contents",
    ),
    (
        "crates/lpm-store/src/v3/cas.rs::ensure_materialized_entry",
        "publishes a complete materialized tree from a randomized private staging directory",
    ),
    (
        "crates/lpm-store/src/v3/cas.rs::replace_with_hardlink",
        "swaps a duplicate object file for its validated CAS hardlink with a randomized rollback backup",
    ),
    (
        "crates/lpm-tunnel/src/webhook_log.rs::perform_rotation",
        "rotates existing log files without writing through temporary leaf paths",
    ),
];

fn rust_sources(root: &Path, sources: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_sources(&path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(())
}

#[test]
fn production_atomic_rewrites_use_exclusive_temporary_files() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("integration crate must live under tests/integration");
    let crates = repository.join("crates");
    let mut sources = Vec::new();
    rust_sources(&crates, &mut sources).expect("enumerate Rust sources");
    sources.sort_unstable();

    let mut findings = Vec::new();
    let mut reviewed = std::collections::BTreeSet::new();
    for source in sources {
        let relative_path = source
            .strip_prefix(repository)
            .expect("source must be below repository root");
        let contents = fs::read_to_string(&source)
            .unwrap_or_else(|error| panic!("read {}: {error}", relative_path.display()));
        let syntax = syn::parse_file(&contents)
            .unwrap_or_else(|error| panic!("parse {}: {error}", relative_path.display()));
        let mut visitor = ProductionFunctionVisitor {
            relative_path,
            findings: Vec::new(),
            reviewed: Vec::new(),
            in_test_module: false,
        };
        visitor.visit_file(&syntax);
        findings.extend(visitor.findings);
        reviewed.extend(visitor.reviewed);
    }

    let stale_allowlist: Vec<_> = REVIEWED_RAW_ATOMIC_WRITERS
        .iter()
        .filter(|(key, reason)| reason.is_empty() || !reviewed.contains(*key))
        .map(|(key, _)| *key)
        .collect();
    assert!(
        stale_allowlist.is_empty(),
        "reviewed raw-replacement inventory contains stale or unexplained entries:\n{}",
        stale_allowlist.join("\n")
    );
    assert!(
        findings.is_empty(),
        "production code contains raw replacements outside the reviewed inventory:\n{}",
        findings.join("\n")
    );
}

#[test]
fn cfg_with_a_production_branch_is_not_test_only() {
    let attribute: syn::Attribute = syn::parse_quote!(#[cfg(any(not(target_os = "macos"), test))]);

    assert!(!attributes_are_test_only(&[attribute]));
}

#[test]
fn cfg_all_branch_that_requires_test_is_test_only() {
    let attribute: syn::Attribute = syn::parse_quote!(#[cfg(all(unix, test))]);

    assert!(attributes_are_test_only(&[attribute]));
}
