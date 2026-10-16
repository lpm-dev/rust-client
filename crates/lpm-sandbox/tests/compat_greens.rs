//! Green-tier compat corpus — each test runs a minimal fixture script
//! that writes to the same shape of paths a real green-tier
//! postinstall (node-gyp rebuild, electron-rebuild, tsc, prisma
//! generate, husky install) would, and asserts the sandbox ALLOWS
//! the writes under [`SandboxMode::Enforce`].
//!
//! These are MINIMAL fixtures: the CI lane exercises the real write
//! shapes without depending on npm / node-gyp / python / build
//! toolchains being installed. A narrow `#[ignore]`-gated real-install
//! lane runs true package installs before rule changes or release
//! work; it's the developer-opt-in safety net, not the default CI
//! matrix.
//!
//! | Fixture            | Real green                | Write shape                                      |
//! |--------------------|---------------------------|--------------------------------------------------|
//! | `node_gyp_rebuild` | node-gyp rebuild          | `{pkg}/build/Release/*.node`, `~/.node-gyp/`     |
//! | `electron_rebuild` | @electron/rebuild         | same shape as node-gyp                           |
//! | `tsc_inplace`      | tsc (project-local build) | `{pkg}/dist/*.js`                                |
//! | `prisma_generate`  | prisma generate           | `{project}/node_modules/.prisma/client/*.js`     |
//! | `husky_install`    | husky install             | `{project}/.husky/<hook>`                        |
//! | `package_dirs_*`   | postinstall in a layout   | `{project}/.lpm/{wrappers,hoisted/nested}/...`   |
//!
//! If any of these tests fail after a sandbox allow-list rule change,
//! the rule change broke a real green pattern — either tighten the
//! fixture to the narrower real behavior or demote the pattern to amber.

mod common;

use common::{SandboxFixture, run_script, sandbox_supported, try_build_sandbox};
use lpm_sandbox::SandboxMode;

#[test]
fn node_gyp_rebuild_shape_succeeds() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("native-pkg", "2.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // Real node-gyp writes:
    // - {pkg_dir}/build/Release/*.node (output binary)
    // - {pkg_dir}/build/Makefile, config.gypi (generated)
    // - $HOME/.node-gyp/<node-version>/include/ (during rebuild)
    // The first two are under the package's own writable root; the
    // third is under $HOME/.node-gyp, which the sandbox explicitly allows.
    let script = "\
        mkdir -p build/Release && \
        echo fake-binary > build/Release/binding.node && \
        echo 'make-rule' > build/Makefile && \
        mkdir -p \"$HOME/.node-gyp/lpm-p5-test\" && \
        echo header > \"$HOME/.node-gyp/lpm-p5-test/header.h\"";
    let status = run_script(sb.as_ref(), &fx.pkg_dir, script);
    assert!(
        status.success(),
        "node-gyp-shape writes must succeed under Enforce — {status:?}"
    );
    assert!(fx.pkg_dir.join("build/Release/binding.node").exists());
    assert!(fx.pkg_dir.join("build/Makefile").exists());
    // Cleanup the $HOME side-effect. The sandbox allowed the write,
    // but the tempdir-scoped fixture can't own a path under $HOME.
    let home_marker = dirs::home_dir()
        .unwrap()
        .join(".node-gyp/lpm-p5-test/header.h");
    assert!(home_marker.exists());
    let _ = std::fs::remove_dir_all(dirs::home_dir().unwrap().join(".node-gyp/lpm-p5-test"));
}

#[test]
fn electron_rebuild_shape_succeeds() {
    // electron-rebuild invokes node-gyp under the hood with a
    // different HOME cache (~/.electron-gyp) on some platforms, but
    // the primary write pattern is identical: {pkg_dir}/build/
    // Release/*.node. The test is deliberately a subset of the
    // node-gyp test so a rule change affecting both is caught
    // exactly once regardless of which fixture hits it first.
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("electron-native", "30.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    let script = "\
        mkdir -p build/Release && \
        echo fake-electron-binary > build/Release/electron-binding.node";
    let status = run_script(sb.as_ref(), &fx.pkg_dir, script);
    assert!(status.success(), "electron-rebuild shape must succeed");
    assert!(
        fx.pkg_dir
            .join("build/Release/electron-binding.node")
            .exists()
    );
}

#[test]
fn tsc_inplace_compile_shape_succeeds() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("typescript-lib", "5.4.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // tsc compiles in-place under the package dir: {pkg}/dist/*.js.
    // Nothing outside the package writable root is touched.
    let script = "\
        mkdir -p dist && \
        echo 'module.exports = {};' > dist/index.js && \
        echo 'export default {};' > dist/index.d.ts";
    let status = run_script(sb.as_ref(), &fx.pkg_dir, script);
    assert!(status.success(), "tsc-shape writes must succeed");
    assert!(fx.pkg_dir.join("dist/index.js").exists());
    assert!(fx.pkg_dir.join("dist/index.d.ts").exists());
}

#[test]
fn prisma_generate_shape_succeeds() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("prisma", "5.22.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // prisma generate writes to {project}/node_modules/.prisma/
    // client/index.js. The path is NOT inside the package's own
    // store dir — it's inside the project's node_modules. The sandbox
    // explicitly allows writes to `{project}/node_modules`.
    let client_dir = fx.project_dir.join("node_modules/.prisma/client");
    let script = format!(
        "\
        mkdir -p {dir} && \
        echo 'generated client' > {dir}/index.js",
        dir = client_dir.display(),
    );
    let status = run_script(sb.as_ref(), &fx.pkg_dir, &script);
    assert!(
        status.success(),
        "prisma-generate writes to {}/index.js under Enforce — {status:?}",
        client_dir.display()
    );
    assert!(client_dir.join("index.js").exists());
}

#[test]
fn husky_install_shape_succeeds() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("husky", "9.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // husky install writes to {project}/.husky/<hook>. The sandbox
    // explicitly allows `{project}/.husky`.
    let husky = fx.project_dir.join(".husky");
    let script = format!(
        "\
        mkdir -p {dir} && \
        echo '#!/bin/sh' > {dir}/pre-commit && \
        chmod +x {dir}/pre-commit",
        dir = husky.display(),
    );
    let status = run_script(sb.as_ref(), &fx.pkg_dir, &script);
    assert!(
        status.success(),
        "husky-install writes to {}/pre-commit under Enforce — {status:?}",
        husky.display()
    );
    assert!(husky.join("pre-commit").exists());
}

#[test]
fn a_package_in_project_state_writes_beside_itself_but_not_into_its_siblings() {
    // The isolated layout keeps packages under {project}/.lpm/wrappers and
    // the hoisted layout keeps nested overrides under
    // {project}/.lpm/hoisted/nested; a postinstall there writes beside its
    // own package (prisma generate's `node_modules/.prisma` shape), but a
    // sibling's files stay read-only.
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("layout-consumer", "1.0.0").with_private_tmpdir();
    let [wrappers, hoisted_nested] = lpm_common::project_package_dirs(&fx.project_dir);
    for (package, beside, sibling) in [
        (
            wrappers.join("client@1.0.0/node_modules/client"),
            wrappers.join("client@1.0.0/node_modules/.prisma/client"),
            wrappers.join("victim@1.0.0/node_modules/victim"),
        ),
        (
            hoisted_nested.join("client"),
            hoisted_nested.join("client/node_modules/.prisma/client"),
            hoisted_nested.join("victim"),
        ),
    ] {
        for directory in [&package, &beside, &sibling] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let mut spec = fx.spec.clone();
        spec.package_dir = package.clone();
        let sb = try_build_sandbox(spec, SandboxMode::Enforce).unwrap();

        let generated = format!(
            "echo 'module.exports = {{}}' > {}/index.js",
            beside.display()
        );
        let status = run_script(sb.as_ref(), &package, &generated);
        assert!(
            status.success(),
            "write beside {} — {status:?}",
            package.display()
        );
        assert!(beside.join("index.js").exists());

        let poisoned = format!("echo 'attack' > {}/index.js", sibling.display());
        let status = run_script(sb.as_ref(), &package, &poisoned);
        assert!(
            !status.success(),
            "write into {} — {status:?}",
            sibling.display()
        );
        assert!(!sibling.join("index.js").exists());
    }
}

#[test]
fn tmp_scratch_write_shape_succeeds() {
    // Many postinstalls shell out to `mktemp` or write directly to
    // /tmp for intermediate artifacts. The sandbox must allow that.
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("tmp-scratch", "1.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    let uniq = format!("lpm-p5-tmp-{}", std::process::id());
    let script = format!("echo scratch > /tmp/{uniq}.txt");
    let status = run_script(sb.as_ref(), &fx.pkg_dir, &script);
    assert!(
        status.success(),
        "writes to /tmp must succeed under Enforce"
    );
    let _ = std::fs::remove_file(format!("/tmp/{uniq}.txt"));
}
