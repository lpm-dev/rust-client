//! Sandbox UDP / raw / AF_PACKET / AF_NETLINK
//! denial — workflow gate.
//!
//! Sibling of [`sandbox_network_denial.rs`] (the TCP
//! gate) and [`sandbox_filesystem_denial.rs`] (P5). The
//! TCP test pins outbound-TCP denial via landlock V4; this test
//! pins the second enforcement layer: a seccomp-bpf filter that
//! denies the `socket(2)` variants landlock V4 doesn't reach.
//!
//! ## What this proves
//!
//! Two cases, both hermetic (no `tcpdump`, no `CAP_NET_ADMIN`,
//! no network namespace setup):
//!
//! 1. **UDP case** — synthetic postinstall calls
//!    `dgram.createSocket('udp4').send(...)`. Node's `dgram`
//!    binding maps to `socket(AF_INET, SOCK_DGRAM)` inside
//!    libuv; the seccomp filter must return
//!    `EACCES` from that syscall, so the send callback fires
//!    with an error and the script exits non-zero. Two
//!    assertions: (a) sandbox-denial token in stderr, (b) the
//!    in-process tokio UdpSocket listener never receives the
//!    probe payload — mirror of the TCP test's
//!    `received_requests().is_empty()` assertion.
//!
//! 2. **Raw / AF_PACKET / AF_NETLINK case** — Node doesn't
//!    natively expose these families. The synthetic postinstall
//!    spawns the `socket-probe` test-bin (built alongside this
//!    workflow crate by cargo) four times, once per family.
//!    `socket-probe` exits 0 iff the kernel returned `EACCES`,
//!    so any non-zero exit from the probe means a family
//!    slipped through the filter. The Node script forwards the
//!    first such failure to its own exit code.
//!
//! ## What this test intentionally does NOT cover
//!
//! - **DNS-via-resolver**: glibc NSS can route through AF_UNIX
//!   (allowed by the seccomp filter) or TCP fallback (caught by
//!   landlock, not seccomp). Both surface as `EAI_*` errors, not
//!   `EACCES`, and the timing is host-dependent. Live audit
//!   coverage (`bench/sandbox-network-audit/`) holds this signal
//!   on the soft `dns_failure_seen` axis instead.
//! - **AF_UNIX containment**: intentionally allowed for
//!   legitimate IPC needs (node-ipc, husky hooks, npm daemon
//!   comms). Tracked as its own follow-up axis.
//!
//! ## Linux-only
//!
//! The UDP/raw seccomp filter is the Linux follow-up to TCP denial; the
//! seccomp filter only installs in the linux backend. macOS
//! Seatbelt already covers every socket family
//! unconditionally (`(deny default)`), so this
//! test would be redundant there.

#![cfg(target_os = "linux")]

mod support;

use std::path::PathBuf;
use std::time::Duration;

use support::assertions;
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

// ─── Test constants ────────────────────────────────────────────────────

const UDP_DEP_NAME: &str = "synthetic-udp-denial";
const FAMILY_DEP_NAME: &str = "synthetic-family-denial";
const DEP_VERSION: &str = "1.0.0";

/// Postinstall body for the UDP case. Reads the listener port
/// from `LPM_TEST_UDP_TARGET_PORT` and tries one `udpSocket.send`
/// against `127.0.0.1:<port>`. Mirrors `sandbox_network_denial.rs`
/// shape: explicit timeout, error surfaced on stderr in a form
/// the sandbox-denial regex catches.
const UDP_INSTALL_JS_BODY: &[u8] = br#"
const dgram = require('dgram');
const port = parseInt(process.env.LPM_TEST_UDP_TARGET_PORT || '0', 10);
if (!port) {
    console.error('LPM_TEST_UDP_TARGET_PORT unset; test harness misconfigured');
    process.exit(2);
}

// Wrap createSocket so a seccomp denial during socket() surfaces
// as a clear stderr line. Some Node versions throw from the
// constructor; others surface the error on the first I/O. Try
// both shapes.
let sock;
try {
    sock = dgram.createSocket('udp4');
} catch (err) {
    console.error('udp-create-failed: code=' + (err.code || '') + ' message=' + (err.message || ''));
    process.exit(1);
}
sock.on('error', (err) => {
    console.error('udp-sock-error: code=' + (err.code || '') + ' message=' + (err.message || ''));
    try { sock.close(); } catch (_) {}
    process.exit(1);
});

// 1-second guard so a kernel that lets the syscall succeed but
// quietly drops the packet doesn't hang the test.
setTimeout(() => {
    console.error('udp-send-timeout');
    try { sock.close(); } catch (_) {}
    process.exit(1);
}, 1000);

sock.send(Buffer.from('udp-probe'), port, '127.0.0.1', (err) => {
    if (err) {
        console.error('udp-send-failed: code=' + (err.code || '') + ' message=' + (err.message || ''));
        try { sock.close(); } catch (_) {}
        process.exit(1);
    }
    // Send completed without the seccomp filter intervening:
    // the listener may also have received the probe. Either
    // way, the filter is NOT installed; surface a distinct
    // stderr message so the test can tell "denied" apart from
    // "succeeded".
    console.error('UNEXPECTED_UDP_SUCCESS to 127.0.0.1:' + port);
    try { sock.close(); } catch (_) {}
    process.exit(1);
});
"#;

/// Postinstall body for the raw / AF_PACKET / AF_NETLINK case.
/// Spawns `LPM_TEST_SOCKET_PROBE_BIN` four times — one per
/// family/type pair — via `child_process.spawnSync`. The probe
/// exits 0 iff the kernel returned `EACCES`; any non-zero exit
/// means a family slipped through and the Node script forwards
/// the failure.
const FAMILY_INSTALL_JS_BODY: &[u8] = br#"
const { spawnSync } = require('child_process');
const probe = process.env.LPM_TEST_SOCKET_PROBE_BIN;
if (!probe) {
    console.error('LPM_TEST_SOCKET_PROBE_BIN unset; test harness misconfigured');
    process.exit(2);
}

// (family, type, label): values lifted from libc on Linux.
//   AF_INET=2, AF_INET6=10, AF_PACKET=17, AF_NETLINK=16
//   SOCK_RAW=3
// (test runs Linux-only; see file header.)
const cases = [
    [2,  3, 'AF_INET/SOCK_RAW'],
    [10, 3, 'AF_INET6/SOCK_RAW'],
    [17, 3, 'AF_PACKET/SOCK_RAW'],
    [16, 3, 'AF_NETLINK/SOCK_RAW'],
];

for (const [family, type, label] of cases) {
    const res = spawnSync(probe, [String(family), String(type), '0'], {
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (res.status !== 0) {
        // socket-probe exits 0 only when errno == EACCES (the
        // deny-matrix outcome). Anything else means the filter
        // either let the socket through (exit 1) or hit a
        // different errno (exit 2, e.g. EAFNOSUPPORT). Either
        // way, surface the probe stderr + exit code so the
        // workflow assertion can see which family slipped.
        console.error('socket-probe FAILED for ' + label + ': status=' + res.status);
        if (res.stderr) {
            process.stderr.write(res.stderr);
        }
        process.exit(1);
    }
}

// All four cases denied: success path.
console.log('all socket families denied');
"#;

// ─── Fixture builders ──────────────────────────────────────────────────

fn build_tarball(dep_name: &str, install_js: &[u8]) -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": dep_name,
        "version": DEP_VERSION,
        "scripts": {
            "postinstall": "node install.js",
        }
    });
    make_tarball_from_pkg_json(pkg_json, &[("install.js", install_js)])
}

fn project_manifest(dep_name: &str) -> String {
    format!(
        r#"{{
    "name": "sandbox-udp-denial-fixture-{dep_name}",
    "version": "1.0.0",
    "dependencies": {{
        "{dep_name}": "^{DEP_VERSION}"
    }}
}}
"#
    )
}

async fn mount_dep(mock: &MockRegistry, dep_name: &str, tarball: &[u8]) {
    mock.with_package(dep_name, DEP_VERSION, tarball).await;
    let tarball_url = format!(
        "{}/tarballs/{dep_name}/-/{dep_name}-{DEP_VERSION}.tgz",
        mock.url()
    );
    let integrity = support::mock_registry::compute_integrity(tarball);
    let version_owned = DEP_VERSION.to_string();
    let mut versions = serde_json::Map::new();
    versions.insert(
        version_owned.clone(),
        serde_json::json!({
            "name": dep_name,
            "version": DEP_VERSION,
            "dist": {
                "tarball": tarball_url,
                "integrity": integrity,
            },
            "dependencies": {}
        }),
    );
    let mut time = serde_json::Map::new();
    time.insert(
        version_owned,
        serde_json::Value::String("2024-01-01T00:00:00.000Z".to_string()),
    );
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": dep_name,
        "dist-tags": { "latest": DEP_VERSION },
        "versions": serde_json::Value::Object(versions),
        "time": serde_json::Value::Object(time),
    })])
    .await;
}

// ─── Observability helpers ─────────────────────────────────────────────

fn lpm_built_marker(project: &TempProject, dep_name: &str) -> PathBuf {
    let safe = dep_name.replace(['/', '\\'], "+");
    project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{DEP_VERSION}"))
        .join(".lpm-built")
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn assert_security_approval_scope(out: &std::process::Output, expected_scope: &str) {
    let envelope = assertions::assert_security_approval_required(out);
    let scopes = envelope["error"]["requested_scopes"]
        .as_array()
        .unwrap_or_else(|| panic!("security approval envelope must include scopes: {envelope}"));
    assert!(
        scopes.iter().any(|scope| scope == expected_scope),
        "security approval envelope must include scope `{expected_scope}`; got {envelope}",
    );
}

fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The directory the test stages `socket-probe` into for exec
/// inside the sandbox. Must be both in landlock's RW allow-list
/// (see [`crates/lpm-sandbox/src/landlock_rules.rs::describe_rules`])
/// and on an exec-capable mount. Prefers `$TMPDIR` (which the
/// install pipeline also reads to populate `spec.tmpdir`,
/// keeping the test and the sandboxed install pipeline aligned
/// on the same allow-listed path) and falls back to `/tmp`.
fn allowlisted_exec_dir() -> PathBuf {
    std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}

/// True iff the most-specific `/proc/mounts` entry covering
/// `path` has the `noexec` option. Mirror of the same helper
/// in `crates/lpm-sandbox/tests/seccomp_socket_deny.rs`.
fn path_is_noexec(path: &std::path::Path) -> bool {
    let target = path.to_string_lossy();
    let mounts = match std::fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut best_len: usize = 0;
    let mut best_noexec = false;
    for line in mounts.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let mountpoint = parts[1];
        let options = parts[3];
        let covers = target == mountpoint
            || target.starts_with(&format!("{mountpoint}/"))
            || mountpoint == "/";
        if covers && mountpoint.len() > best_len {
            best_len = mountpoint.len();
            best_noexec = options.split(',').any(|o| o == "noexec");
        }
    }
    best_noexec
}

fn signals_sandbox_denial(combined: &str) -> bool {
    // Mirror of `sandbox_network_denial.rs`'s token set — keep
    // both files in lock-step so the audit harness's
    // `denial_signal_seen` regex (`run.sh:140-155`) is the one
    // source of truth.
    combined.contains("EPERM")
        || combined.contains("EACCES")
        || combined.contains("EHOSTUNREACH")
        || combined.contains("ENETUNREACH")
        || combined.contains("operation not permitted")
        || combined.contains("Operation not permitted")
        || combined.contains("permission denied")
        || combined.contains("Permission denied")
}

// ─── Tests ─────────────────────────────────────────────────────────────

/// UDP case (load-bearing). Synthetic postinstall
/// opens a `dgram` socket and `send`s a probe payload to a
/// tokio-bound UDP listener at `127.0.0.1:<port>`. The seccomp
/// filter MUST return EACCES from the underlying `socket(AF_INET,
/// SOCK_DGRAM)` syscall, so neither the send nor the listener's
/// recv ever sees the payload.
///
/// Linux-only: macOS Seatbelt already denies UDP unconditionally;
/// This is the Linux-side parity push for the families
/// landlock V4 leaves open.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn postinstall_udp_send_is_denied_listener_silent() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let exec_dir = allowlisted_exec_dir();
    if path_is_noexec(&exec_dir) {
        eprintln!(
            "skipping: chosen exec staging dir {} is on a noexec mount. \
             The test copies socket-probe there and execs it under the \
             sandbox; noexec masks seccomp denial with a kernel-mount \
             EACCES. To run: set TMPDIR to a directory on an exec-capable \
             mount, or remount the underlying filesystem without `noexec`.",
            exec_dir.display(),
        );
        return;
    }

    // Bind an OS-assigned port; pass via env to the synthetic
    // postinstall. The tokio listener stays in this process for
    // the duration of the install — when the install ends, the
    // socket is dropped and recv stops.
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP listener on loopback");
    let listener_port = listener.local_addr().expect("local_addr").port();

    let mock = MockRegistry::start().await;
    let tarball = build_tarball(UDP_DEP_NAME, UDP_INSTALL_JS_BODY);
    mount_dep(&mock, UDP_DEP_NAME, &tarball).await;

    let project = TempProject::empty(&project_manifest(UDP_DEP_NAME));

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "--policy=allow"])
        .env("LPM_STRICT_SANDBOX", "1")
        .env("LPM_TEST_UDP_TARGET_PORT", listener_port.to_string())
        .output()
        .expect("spawn lpm install");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let combined = format!("{stderr}\n{stdout}");

    if combined.contains("\"SECURITY_APPROVAL_REQUIRED\"") {
        assert_security_approval_scope(&out, "scripts-allow");
        let marker = lpm_built_marker(&project, UDP_DEP_NAME);
        assert!(
            !marker.exists(),
            ".lpm-built marker must remain absent when scripts-allow approval is missing: {}",
            marker.display(),
        );
        return;
    }

    // ── Assertion 0: trusted auto-build failures fail install. ──
    assert!(
        !out.status.success(),
        "install exit code MUST be non-zero when a trusted lifecycle script fails during \
         auto-build. \
         Got: {:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        out.status,
    );

    // ── Assertion 1: sandbox denial signal in stderr. ──
    assert!(
        signals_sandbox_denial(&combined),
        "seccomp denial signal absent from install output. \
         Without EPERM / EACCES / 'operation not permitted' / 'permission denied' \
         in stderr, the script failure could have any cause; the test asserts \
         SANDBOX enforcement of UDP socket() specifically.\n\
         stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    // ── Assertion 2: build pipeline observed the failure. ──
    let acknowledged = combined.contains("postinstall failed")
        || combined.contains("Auto-build failed")
        || combined.contains("failed to build");
    assert!(
        acknowledged,
        "install must observe the postinstall failure (per-package \
         'postinstall failed' OR aggregate 'Auto-build failed' / 'failed to build'). \
         A silent success here is a contract regression.\n\
         stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    // ── Assertion 3: `.lpm-built` marker absent. ──
    let marker = lpm_built_marker(&project, UDP_DEP_NAME);
    assert!(
        !marker.exists(),
        ".lpm-built marker MUST be absent after a sandbox-denied lifecycle script; \
         found at {}\nstderr:\n{stderr}",
        marker.display(),
    );

    // ── Assertion 4: listener received zero packets. ──
    //
    // The seccomp filter blocks `socket()` itself, so the send
    // never gets a packet onto the wire. If the listener
    // receives anything, the filter let the syscall through —
    // same severity as the TCP test's
    // `received_requests().is_empty()` assertion. 100ms is
    // plenty: the loopback path normally delivers a UDP packet
    // in microseconds, and if the filter denied at socket() the
    // packet is GUARANTEED never to leave the box.
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_millis(100), listener.recv(&mut buf)).await {
        Err(_) => {
            // Timeout: nothing arrived — the contract we want.
        }
        Ok(Ok(n)) => panic!(
            "seccomp filter let a UDP packet through. Listener \
             received {n} bytes: {:?}\nstderr:\n{stderr}",
            &buf[..n.min(buf.len())],
        ),
        Ok(Err(e)) => panic!("UDP listener recv errored unexpectedly: {e}\nstderr:\n{stderr}"),
    }
}

/// Raw / AF_PACKET / AF_NETLINK case. Synthetic postinstall
/// spawns the `socket-probe` test bin four times, once per
/// family. Each probe exits 0 iff the kernel returned `EACCES`;
/// the script exits non-zero on the first probe that didn't get
/// the deny-matrix outcome.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn postinstall_raw_packet_netlink_sockets_are_denied() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let exec_dir = allowlisted_exec_dir();
    if path_is_noexec(&exec_dir) {
        eprintln!(
            "skipping: chosen exec staging dir {} is on a noexec mount. \
             The test copies socket-probe there and execs it under the \
             sandbox; noexec masks seccomp denial with a kernel-mount \
             EACCES. To run: set TMPDIR to a directory on an exec-capable \
             mount, or remount the underlying filesystem without `noexec`.",
            exec_dir.display(),
        );
        return;
    }

    // Locate the workflows-local `workflows-socket-probe` test bin.
    // `cargo_bin!` only
    // works for same-crate integration tests; this workflow
    // crate is separate from `lpm-sandbox` where `socket-probe`
    // lives. Resolve at runtime from `current_exe()`:
    //   current_exe = target/<profile>/deps/<test>-<hash>
    //   bin         = target/<profile>/workflows-socket-probe
    // The workflows-local `[[bin]]` in `tests/workflows/Cargo.toml`
    // makes cargo build that bin before this test runs, so it's
    // guaranteed present without depending on `lpm-sandbox`'s own
    // output name.
    let src_probe = match std::env::var_os("LPM_TEST_SOCKET_PROBE_SOURCE") {
        Some(p) => PathBuf::from(p),
        None => {
            let test_exe = std::env::current_exe().expect("current_exe");
            let target_dir = test_exe
                .parent()
                .and_then(std::path::Path::parent)
                .expect("test binary lives at target/<profile>/deps/<file>");
            target_dir.join("workflows-socket-probe")
        }
    };
    assert!(
        src_probe.exists(),
        "workflows-socket-probe test bin not at {}. Cargo should build it \
         via the local `[[bin]]` in `tests/workflows/Cargo.toml`. If \
         running with a custom CARGO_TARGET_DIR, set \
         `LPM_TEST_SOCKET_PROBE_SOURCE=<absolute path>` before invoking \
         the test.",
        src_probe.display(),
    );

    // Landlock's default rule set
    // (`crates/lpm-sandbox/src/landlock_rules.rs::describe_rules`)
    // allows read on `/tmp`, `spec.tmpdir`, and the project
    // tree, but NOT on arbitrary cargo target dirs. The
    // synthetic postinstall spawns `socket-probe` via
    // `child_process.spawnSync`, which inherits the sandbox;
    // an exec on a path outside the allow-list fails with
    // EACCES before the seccomp filter can return its own
    // EACCES from `socket(2)`. Copy the bin into the
    // allow-listed exec dir picked by `allowlisted_exec_dir()`
    // (TMPDIR if set, else /tmp — the same path that
    // populates `spec.tmpdir`) so the test pins seccomp denial
    // of socket(2), the actual contract.
    let probe_tmpdir = tempfile::tempdir_in(&exec_dir)
        .unwrap_or_else(|e| panic!("tempdir under {}: {e}", exec_dir.display()));
    let probe = probe_tmpdir.path().join("socket-probe");
    std::fs::copy(&src_probe, &probe).expect("copy socket-probe into exec_dir");
    use std::os::unix::fs::PermissionsExt as _;
    let mut perm = std::fs::metadata(&probe).expect("metadata").permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&probe, perm).expect("chmod 0755");

    let mock = MockRegistry::start().await;
    let tarball = build_tarball(FAMILY_DEP_NAME, FAMILY_INSTALL_JS_BODY);
    mount_dep(&mock, FAMILY_DEP_NAME, &tarball).await;

    let project = TempProject::empty(&project_manifest(FAMILY_DEP_NAME));

    let out = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "--policy=allow"])
        .env("LPM_STRICT_SANDBOX", "1")
        .env("LPM_TEST_SOCKET_PROBE_BIN", probe.as_os_str())
        .output()
        .expect("spawn lpm install");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let combined = format!("{stderr}\n{stdout}");

    if combined.contains("\"SECURITY_APPROVAL_REQUIRED\"") {
        assert_security_approval_scope(&out, "scripts-allow");
        let marker = lpm_built_marker(&project, FAMILY_DEP_NAME);
        assert!(
            !marker.exists(),
            ".lpm-built marker must remain absent when scripts-allow approval is missing: {}",
            marker.display(),
        );
        return;
    }

    // L13 fail-closed: some kernel builds (notably the GitHub
    // Actions Ubuntu runners as of 2026-05) advertise landlock V4
    // ABI but only partially wire BindTcp/ConnectTcp under the
    // LSM. The L13 closure refuses to install the strict sandbox
    // in that state rather than silently degrade the network-deny
    // claim. The lpm-sandbox child surfaces this as
    //   `landlock: PartiallyEnforced under strict posture; refusing`
    // on stderr, and the postinstall never runs — so the
    // "all socket families denied" success line is naturally
    // absent. Skip rather than fail when we see that exact
    // surface; the test is meaningless on a host where strict
    // can't be delivered. Hosts that DO deliver FullyEnforced
    // still exercise the full deny-matrix assertion below.
    if combined.contains("PartiallyEnforced under strict posture; refusing") {
        eprintln!(
            "skipping: kernel landlock V4 is PartiallyEnforced on this host; \
             L13 fail-closed refused the strict sandbox install. \
             stderr signal: 'PartiallyEnforced under strict posture; refusing'",
        );
        return;
    }

    assert!(
        out.status.success(),
        "install exit code MUST be 0 when the socket-family probe confirms every \
         family was denied and exits successfully. \
         Got: {:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        out.status,
    );

    // The seccomp filter denied each family — socket-probe exited
    // 0 in every case and the Node script printed
    // "all socket families denied" to stdout. We assert (a) the
    // sandbox denial signal IS NOT present (because the postinstall
    // succeeded — the script saw EACCES from each probe, which is
    // what it wanted), and (b) the success line is present.
    //
    // Inverted logic for clarity: if the filter DIDN'T deny a
    // family, the postinstall exits 1 and the build pipeline
    // surfaces "Auto-build failed" or "postinstall failed",
    // which signals_sandbox_denial would not see (its tokens are
    // OS-level errno strings, not lpm-side failure prose).
    let success_marker = combined.contains("all socket families denied");
    if !success_marker {
        // The script didn't print the success line — at least
        // one family slipped through. Surface the full output
        // so the test author can see WHICH family failed.
        panic!(
            "seccomp filter let at least one of raw / AF_PACKET / \
             AF_NETLINK socket() through. Expected 'all socket families denied' \
             in stdout. signals_sandbox_denial={}\n\
             stderr:\n{stderr}\nstdout:\n{stdout}",
            signals_sandbox_denial(&combined),
        );
    }

    // `.lpm-built` marker SHOULD be present here — the postinstall
    // exited 0 because every family was denied as expected. This
    // is a positive-path assertion, distinct from the UDP case
    // (which asserts the absent-marker contract).
    let marker = lpm_built_marker(&project, FAMILY_DEP_NAME);
    assert!(
        marker.exists(),
        ".lpm-built marker MUST be present when the postinstall succeeded \
         (every family denied as expected). Missing at {}\nstderr:\n{stderr}",
        marker.display(),
    );
}
