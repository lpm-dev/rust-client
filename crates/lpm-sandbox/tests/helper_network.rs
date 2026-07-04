//! Outbound-network denial integration tests for
//! `lpm-sandbox-helper.exe` under Strict (no capabilities) and the
//! per-cap variant.
//!
//! Tier: cli-binary (integration). The cross-platform
//! [`tests/workflows/tests/sandbox_network_denial.rs`] holds the
//! end-to-end gate against `lpm install --strict-sandbox`; this
//! file isolates the helper-side contract:
//!
//! - **Strict (no `--grant-internet-client`)** denies outbound TCP
//!   to *every* target (loopback and non-loopback) at the AppContainer
//!   / WFP boundary, with a recognizable error signal in stderr.
//! - The denial signal AppContainer surfaces is either `WSAEACCES`
//!   (10013, "forbidden by its access permissions" — synchronous
//!   kernel refusal) or `WSAETIMEDOUT` (10060, "did not properly
//!   respond after a period of time" — WFP silent-drop policy).
//!   Both are produced by the same AppContainer/WFP boundary;
//!   which one surfaces depends on the Windows kernel version and
//!   the WFP filter configuration. WSAEACCES is the synchronous
//!   refusal; observed behavior on Windows 11 26200 surfaces
//!   WSAETIMEDOUT for loopback + TEST-NET targets. Both shapes
//!   prove kernel-level denial — outside AppContainer, a
//!   loopback-listener connect succeeds in <1ms, so any timeout
//!   from inside AppContainer is the WFP filter rejecting the
//!   connect.
//!
//! ## What this file does NOT cover
//!
//! The Default-mode positive control ("with `--grant-internet-client`
//! the connect succeeds") is NOT a per-helper test because
//! AppContainer blocks loopback **even with `InternetClient`** —
//! enabling loopback in AppContainer requires
//! `NetIsolationSetAppContainerConfig` + `privateNetworkClientServer`,
//! both admin-only, and a non-loopback target is not hermetic on
//! CI. The cross-platform workflow test handles that contract on
//! macOS + Linux.

#![cfg(target_os = "windows")]

use assert_cmd::Command;
use std::net::TcpListener;

const TEST_APPCONTAINER_NAME: &str = "LpmSandboxHelperIntegrationTest";

fn minimal_argv(grant_internet: bool) -> Vec<&'static str> {
    let mut v = vec![
        "--protocol-version",
        "1",
        "--appcontainer-name",
        TEST_APPCONTAINER_NAME,
        "--stdio-stdin",
        "null",
        "--stdio-stdout",
        "null",
        "--stdio-stderr",
        "piped",
    ];
    if grant_internet {
        v.push("--grant-internet-client");
    }
    v
}

/// PowerShell one-liner that tries one `TcpClient.BeginConnect`
/// with a bounded wait so the test fails fast rather than blocking
/// on `TcpClient.Connect`'s ~21-second default. AppContainer Strict
/// either:
///
///   - Refuses synchronously with WSAEACCES (10013), surfacing as
///     a fired exception during BeginConnect, OR
///   - Silently drops the SYN, surfacing as the `Wait(timeout)`
///     returning `false` before any handshake completes.
///
/// Either path exits 1 with a denial-shape stderr line; success
/// (the AppContainer wrongly allowed the connect) would emit the
/// [`SUCCESS_SENTINEL`] on stdout.
const SUCCESS_SENTINEL: &str = "LPM_HELPER_TEST_CONNECTED_OK";

const PS_CONNECT_TEMPLATE: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect('__HOST__', __PORT__, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne(3000, $false)
    if ($ok) {
        $c.EndConnect($iar)
        Write-Output 'LPM_HELPER_TEST_CONNECTED_OK'
        $c.Close()
    } else {
        Write-Error "DENIAL: connect timed out (WFP silent drop)"
        $c.Close()
        exit 1
    }
} catch {
    Write-Error "DENIAL: $_"
    exit 1
}
"#;

fn ps_connect_script(host: &str, port: u16) -> String {
    PS_CONNECT_TEMPLATE
        .replace("__HOST__", host)
        .replace("__PORT__", &port.to_string())
}

/// Substrings any one of which proves an AppContainer/WFP-shaped
/// denial. Either surface (synchronous WSAEACCES or async timeout)
/// counts because the underlying cause is the same kernel filter.
const DENIAL_SIGNALS: &[&str] = &[
    "forbidden by its access permissions", // WSAEACCES (10013)
    "DENIAL:",                             // our PS wrapper prefix
    "did not properly respond after a period of time", // WSAETIMEDOUT
    "connected host has failed to respond", // same
];

/// Bind a TCP listener to a random loopback port and hold the
/// listener live for the duration of the test. The helper child's
/// AppContainer-side connect attempt should be denied at the
/// kernel before the listener accepts anything; the listener
/// exists so a regression that bypasses denial would actually
/// succeed in connecting (rather than failing with ECONNREFUSED
/// and confusing the diagnosis).
fn bind_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("bind loopback listener")
}

fn run_helper_with_powershell(
    argv: &[&str],
    ps_script: &str,
) -> (std::process::ExitStatus, String, String) {
    let mut full_argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    full_argv.push("--".to_string());
    full_argv.push(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string());
    full_argv.push("-NoProfile".to_string());
    full_argv.push("-NonInteractive".to_string());
    full_argv.push("-Command".to_string());
    full_argv.push(ps_script.to_string());
    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&full_argv)
        .output()
        .expect("spawn helper");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status, stdout, stderr)
}

fn assert_denial_signal(stdout: &str, stderr: &str, case: &str) {
    let combined = format!("{stdout}\n{stderr}");
    let signal = DENIAL_SIGNALS.iter().find(|s| combined.contains(*s));
    assert!(
        signal.is_some(),
        "[{case}] expected an AppContainer/WFP denial signal in output (one of: {DENIAL_SIGNALS:?}); got:\n{combined}",
    );
    // Belt: positive marker that the connect did NOT succeed. The
    // sentinel is checked against stdout ONLY (not combined),
    // because PowerShell's error rendering echoes the failing
    // script source — which contains the sentinel string literally
    // — into stderr. A genuine success would write the sentinel to
    // stdout via `Write-Output`; a failure leaves stdout empty
    // (the catch path writes to stderr).
    assert!(
        !stdout.contains(SUCCESS_SENTINEL),
        "[{case}] connect must NOT have succeeded (sentinel `{SUCCESS_SENTINEL}` found in stdout); stdout: {stdout}\nstderr: {stderr}",
    );
}

#[test]
fn helper_strict_denies_outbound_tcp_to_loopback_listener() {
    // Bind an open listener so that — outside AppContainer — a
    // connect would succeed in milliseconds. Any timeout/refusal
    // observed from inside AppContainer is therefore the WFP
    // boundary denying the connect, not a missing peer.
    let listener = bind_listener();
    let port = listener.local_addr().expect("local_addr").port();
    let ps = ps_connect_script("127.0.0.1", port);
    let (status, stdout, stderr) = run_helper_with_powershell(&minimal_argv(false), &ps);
    assert!(
        !status.success(),
        "strict-mode TCP connect to loopback listener must fail; got stdout: {stdout}\nstderr: {stderr}",
    );
    assert_denial_signal(&stdout, &stderr, "loopback");
    drop(listener);
}

#[test]
fn helper_strict_denies_outbound_tcp_to_routable_public_target() {
    // 1.1.1.1 (Cloudflare DNS) is a routable, near-universally
    // reachable public IP. Strict mode without InternetClient
    // denies the connect at the kernel before any packet hits the
    // wire. On hosts with internet access, the manual smoke test
    // On hosts with internet access, WSAEACCES (synchronous denial)
    // on hosts without internet, WSAETIMEDOUT is the surface.
    // Either signal proves denial; both are accepted.
    let ps = ps_connect_script("1.1.1.1", 80);
    let (status, stdout, stderr) = run_helper_with_powershell(&minimal_argv(false), &ps);
    assert!(
        !status.success(),
        "strict-mode public-IP connect must fail; got stdout: {stdout}\nstderr: {stderr}",
    );
    assert_denial_signal(&stdout, &stderr, "public-ip");
}
