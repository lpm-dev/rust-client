//! Regenerates the Windows API bindings that `lpm-cli` commits.
//!
//! Run `cargo run --locked -p lpm-windows-bindgen` after changing a filter
//! file or bumping `windows-bindgen`. The metadata comes bundled with
//! `windows-bindgen`, so this runs on any host without a Windows SDK. CI runs
//! it and fails when the committed bindings differ from its output.

use std::path::Path;

const WINDOWS_HELLO_FILTERS: &str = "crates/lpm-windows-bindgen/filters/windows_hello.txt";
const WINDOWS_HELLO_BINDINGS: &str =
    "crates/lpm-cli/src/security_approval/windows_hello_bindings.rs";

fn main() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the generator lives two directories below the workspace root");
    // windows-bindgen formats its output by running `rustfmt` from the current
    // directory. From the workspace root, rustup resolves the toolchain that
    // `rust-toolchain.toml` pins, the same one `cargo fmt --check` uses.
    std::env::set_current_dir(workspace_root).unwrap_or_else(|err| {
        panic!(
            "failed to enter the workspace root {}: {err}",
            workspace_root.display()
        )
    });

    windows_bindgen::Bindgen::new()
        .filter_file(WINDOWS_HELLO_FILTERS)
        .output(WINDOWS_HELLO_BINDINGS)
        .flat()
        .write();
}
