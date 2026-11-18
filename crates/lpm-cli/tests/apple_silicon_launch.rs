//! **Tier placement: cli-binary.** Justification class: **intentionally
//! minimal binary-surface repro**. The property under test is how the
//! linker wrote the `lpm-rs` executable itself, which only the built binary
//! shows; the workflow harness runs it but can't inspect it.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn apple_silicon_binary_links_with_chained_fixups() {
    let output = std::process::Command::new("otool")
        .args(["-l", env!("CARGO_BIN_EXE_lpm-rs")])
        .output()
        .expect("otool runs");
    assert!(output.status.success(), "otool failed: {output:?}");
    let load_commands = String::from_utf8_lossy(&output.stdout);
    assert!(
        load_commands.contains("LC_DYLD_CHAINED_FIXUPS"),
        "lpm-rs was linked with classic rebase opcodes, which dyld applies at every launch"
    );
}
