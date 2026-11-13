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
}
