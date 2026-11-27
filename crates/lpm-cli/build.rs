//! Windows takes a program whose name holds "install", "setup", "update" or
//! "patch" for an installer, and asks to elevate it before it starts, so an
//! unelevated terminal gets os error 740, unless the program's manifest
//! says what rights it needs. Test targets here have such names, so the
//! linker embeds a manifest in each test binary, whose default UAC entry
//! runs it as its caller (`asInvoker`).
fn compress_embedded_asset(relative_src: &str, output_name: &str) {
    use std::io::Write as _;

    println!("cargo:rerun-if-changed={relative_src}");
    let raw = std::fs::read(relative_src)
        .unwrap_or_else(|error| panic!("failed to read embedded asset {relative_src}: {error}"));
    let out_dir = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").expect("OUT_DIR must be set for build script"),
    );
    let mut encoder = flate2::GzBuilder::new().mtime(0).write(
        Vec::with_capacity(raw.len() / 3),
        flate2::Compression::best(),
    );
    encoder
        .write_all(&raw)
        .expect("gzip compression of embedded asset must succeed");
    let compressed = encoder
        .finish()
        .expect("gzip finish for embedded asset must succeed");
    std::fs::write(out_dir.join(output_name), compressed)
        .unwrap_or_else(|error| panic!("failed to write compressed asset {output_name}: {error}"));
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    compress_embedded_asset(
        "src/commands/skills/dashboard/assets/dashboard.css",
        "dashboard.css.gz",
    );
    compress_embedded_asset(
        "src/commands/skills/dashboard/assets/dashboard.js",
        "dashboard.js.gz",
    );
    compress_embedded_asset("src/templates/graph.html", "graph.html.gz");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Drop unused system dylib load commands (such as libiconv.2.dylib),
        // while preserving LocalAuthentication for objc2's runtime LAContext lookup.
        println!("cargo:rustc-link-arg-bins=-Wl,-dead_strip_dylibs");
        println!("cargo:rustc-link-arg-bins=-Wl,-needed_framework,LocalAuthentication");
    }
    // Rust's arm64 macOS deployment target (11.0) leaves ld64 writing classic
    // rebase opcodes, which dyld applies to ~72k pointers at every launch.
    // Chained fixups, which arm64 macOS 11 supports, cost a fraction of that
    // and are applied lazily at page-in from macOS 13.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
    {
        println!("cargo:rustc-link-arg-bins=-Wl,-fixup_chains");
    }
}
