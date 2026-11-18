//! Windows takes a program whose name holds "install", "setup", "update" or
//! "patch" for an installer, and asks to elevate it before it starts, so an
//! unelevated terminal gets os error 740, unless the program's manifest
//! says what rights it needs. Test targets here have such names, so the
//! linker embeds a manifest in each test binary, whose default UAC entry
//! runs it as its caller (`asInvoker`).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
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
