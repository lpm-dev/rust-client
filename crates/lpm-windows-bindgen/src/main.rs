//! Regenerates the Windows API bindings that `lpm-cli` commits.
//!
//! Run `cargo run --locked -p lpm-windows-bindgen` after changing a filter
//! file or bumping `windows-bindgen`. The metadata comes bundled with
//! `windows-bindgen`, so this runs on any host without a Windows SDK. It
//! formats with the `rustfmt` of the toolchain that `rust-toolchain.toml`
//! pins, which rustup must have installed. CI runs it and fails when the
//! committed bindings differ from its output.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

const WINDOWS_HELLO_FILTERS: &str = "crates/lpm-windows-bindgen/filters/windows_hello.txt";
const WINDOWS_HELLO_BINDINGS: &str =
    "crates/lpm-cli/src/security_approval/windows_hello_bindings.rs";

fn main() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the generator lives two directories below the workspace root");
    // windows-bindgen runs `rustfmt` in the current directory, so from the
    // workspace root it reads the workspace's `rustfmt.toml` rather than a
    // configuration file above the checkout or in the user's profile.
    std::env::set_current_dir(workspace_root).unwrap_or_else(|err| {
        panic!(
            "failed to enter the workspace root {}: {err}",
            workspace_root.display()
        )
    });

    // windows-bindgen runs whichever `rustfmt` comes first on PATH, which may be
    // a standalone install or a rustup proxy that `RUSTUP_TOOLCHAIN` redirects.
    let path = path_with_pinned_rustfmt_first();
    // SAFETY: The process has no other threads yet, so nothing reads the
    // environment while it changes.
    unsafe { std::env::set_var("PATH", path) };

    windows_bindgen::Bindgen::new()
        .filter_file(WINDOWS_HELLO_FILTERS)
        .output(WINDOWS_HELLO_BINDINGS)
        .flat()
        .write();
}

fn path_with_pinned_rustfmt_first() -> OsString {
    let rustfmt_dir = pinned_rustfmt()
        .parent()
        .expect("rustup reports rustfmt inside a toolchain directory")
        .to_path_buf();
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(std::iter::once(rustfmt_dir).chain(std::env::split_paths(&path)))
        .unwrap_or_else(|err| panic!("failed to put the pinned rustfmt first on PATH: {err}"))
}

fn pinned_rustfmt() -> PathBuf {
    let toolchain = pinned_toolchain();
    let output = Command::new("rustup")
        .args(["which", "rustfmt", "--toolchain", &toolchain])
        .output()
        .unwrap_or_else(|err| panic!("failed to run rustup to find the pinned rustfmt: {err}"));
    assert!(
        output.status.success(),
        "rustup found no rustfmt for toolchain {toolchain}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let rustfmt = String::from_utf8(output.stdout).expect("rustup printed a UTF-8 path");
    PathBuf::from(rustfmt.trim())
}

fn pinned_toolchain() -> String {
    let manifest = std::fs::read_to_string("rust-toolchain.toml")
        .unwrap_or_else(|err| panic!("failed to read rust-toolchain.toml: {err}"));
    let manifest: toml::Table = manifest
        .parse()
        .unwrap_or_else(|err| panic!("failed to parse rust-toolchain.toml: {err}"));
    manifest
        .get("toolchain")
        .and_then(|toolchain| toolchain.get("channel"))
        .and_then(toml::Value::as_str)
        .expect("rust-toolchain.toml names a toolchain channel")
        .to_owned()
}
