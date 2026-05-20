//! `socket-probe`: tiny test-only binary that opens a single
//! `socket(family, type, protocol)` and reports the outcome on
//! stderr. Used by:
//!
//! - The `denies_udp_socket_under_strict` unit test in
//!   `crates/lpm-sandbox/src/linux.rs::tests` .
//! - The `sandbox_udp_denial` workflow test in
//!   `tests/workflows/tests/sandbox_udp_denial.rs` .
//!
//! Cross-platform: any non-Linux build emits an `unsupported`
//! line and exits non-zero so a misdirected invocation surfaces
//! a clear error instead of silently passing.
//!
//! Output contract (stderr, single line):
//!   `socket-probe: family=<n> type=<n> proto=<n> rc=<n> errno=<n>`
//!
//! Exit code:
//!   - 0 when `socket(2)` returned `EACCES` (the deny-matrix
//!     outcome the seccomp filter must produce). This makes the
//!     binary trivially testable: `assert!(status.success())`
//!     proves the kernel denied the syscall.
//!   - 1 when `socket(2)` returned an fd (i.e., the filter did
//!     NOT deny — what we want the test to catch).
//!   - 2 for any other failure (argv parsing, unexpected errno).
//!
//! ## Why not the workflow's `install.js`-style Node snippet
//!
//! Node doesn't natively expose AF_PACKET / AF_NETLINK / SOCK_RAW
//! without native modules. A direct libc call lets a single
//! binary cover the full deny matrix; the workflow test invokes
//! it from a tiny Node postinstall that just shells out via
//! `child_process.spawnSync`.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "socket-probe: usage: {} <family-int> <type-int> [protocol-int]",
            args.first().map_or("socket-probe", String::as_str),
        );
        std::process::exit(2);
    }
    let family: i32 = match args[1].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("socket-probe: failed to parse family `{}`: {e}", args[1]);
            std::process::exit(2);
        }
    };
    let sock_type: i32 = match args[2].parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("socket-probe: failed to parse type `{}`: {e}", args[2]);
            std::process::exit(2);
        }
    };
    let proto: i32 = if let Some(p) = args.get(3) {
        match p.parse() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("socket-probe: failed to parse protocol `{p}`: {e}");
                std::process::exit(2);
            }
        }
    } else {
        0
    };
    probe(family, sock_type, proto);
}

#[cfg(target_os = "linux")]
fn probe(family: i32, sock_type: i32, proto: i32) {
    // SAFETY: `libc::socket` is a thin wrapper over the
    // `socket(2)` syscall. All three args are validated `i32`s
    // (parsed from argv above); the kernel rejects invalid
    // combinations with `EINVAL` / `EAFNOSUPPORT`. No invariants
    // to uphold beyond passing the integers through.
    let rc = unsafe { libc::socket(family, sock_type, proto) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    eprintln!("socket-probe: family={family} type={sock_type} proto={proto} rc={rc} errno={errno}");
    if rc >= 0 {
        // Close the fd so the test runner doesn't leak it. A
        // bare close — if the kernel had denied us, we'd never
        // reach here. SAFETY: `rc` is a valid fd from a
        // successful `socket(2)`.
        unsafe {
            libc::close(rc);
        }
        // Exit 1 = "filter did NOT deny" — the test asserts the
        // opposite, so this trips it.
        std::process::exit(1);
    }
    if errno == libc::EACCES {
        // The exact outcome the seccomp filter
        // produces — exit 0 so the unit / workflow test asserts
        // `status.success()`.
        std::process::exit(0);
    }
    // Some other failure (EAFNOSUPPORT on hosts without IPv6,
    // EPROTONOSUPPORT, etc.). Exit 2 so the test distinguishes
    // "filter denied" from "kernel rejected for unrelated
    // reasons" without conflating the two.
    std::process::exit(2);
}

#[cfg(not(target_os = "linux"))]
fn probe(_family: i32, _sock_type: i32, _proto: i32) {
    eprintln!(
        "socket-probe: unsupported on non-Linux targets — \
         this binary exists only to validate the \
         seccomp filter, which is Linux-only."
    );
    std::process::exit(2);
}
