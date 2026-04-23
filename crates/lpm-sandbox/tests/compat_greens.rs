//! §12.5 green-tier compat corpus — each test runs a minimal
//! fixture script that writes to the same shape of paths a real
//! green-tier postinstall (node-gyp rebuild, electron-rebuild, tsc,
//! prisma generate, husky install) would, and asserts the sandbox
//! ALLOWS the writes under [`SandboxMode::Enforce`].
//!
//! These are MINIMAL fixtures (per Chunk 5 hybrid approach signoff):
//! the CI lane exercises the real write shapes without depending on
//! npm / node-gyp / python / build toolchains being installed. A
//! narrow `#[ignore]`-gated real-install lane (Chunk 5b) runs true
//! package installs before rule changes or release work; it's the
//! developer-opt-in safety net, not the default CI matrix.
//!
//! | Fixture            | Real green                | Write shape                                      |
//! |--------------------|---------------------------|--------------------------------------------------|
//! | `node_gyp_rebuild` | node-gyp rebuild          | `{pkg}/build/Release/*.node`, `~/.node-gyp/`     |
//! | `electron_rebuild` | @electron/rebuild         | same shape as node-gyp                           |
//! | `tsc_inplace`      | tsc (project-local build) | `{pkg}/dist/*.js`                                |
//! | `prisma_generate`  | prisma generate           | `{project}/node_modules/.prisma/client/*.js`     |
//! | `husky_install`    | husky install             | `{project}/.husky/<hook>`                        |
//!
//! If any of these tests fail after a §9.3 rule change, the rule
//! change broke a real green pattern — either tighten the fixture
//! to the narrower real behavior or demote the pattern to amber
//! per §9.4's failure-mode table.

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
    // third is under $HOME/.node-gyp, which §9.3 explicitly allows.
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
    // store dir — it's inside the project's node_modules. §9.3
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
    // husky install writes to {project}/.husky/<hook>. §9.3
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
fn lpm_state_write_shape_succeeds() {
    // Not a "green" in the npm-ecosystem sense, but LPM's own state
    // writes (under {project}/.lpm) go through the same sandbox
    // profile and must be permitted. If this breaks, build-state.json
    // writes from inside scripts (which is uncommon but not
    // impossible) would silently fail. §9.3 lists `{project}/.lpm`
    // in the writable set.
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("lpm-state-consumer", "1.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    let dotlpm = fx.project_dir.join(".lpm");
    let script = format!(
        "\
        mkdir -p {dir} && \
        echo '{{}}' > {dir}/state.json",
        dir = dotlpm.display(),
    );
    let status = run_script(sb.as_ref(), &fx.pkg_dir, &script);
    assert!(
        status.success(),
        "write to {}/.lpm must succeed",
        dotlpm.display()
    );
    assert!(dotlpm.join("state.json").exists());
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
