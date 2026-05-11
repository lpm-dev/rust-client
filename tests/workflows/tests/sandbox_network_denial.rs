//! End-to-end contract: the install-time sandbox denies outbound
//! TCP from a lifecycle script, and the install surfaces that
//! failure truthfully.
//!
//! Scope (explicit): **outbound TCP denial only.** This test
//! exercises what Phase 46.1's locked mechanism actually delivers
//! across platforms:
//!
//! - **macOS Seatbelt** — `(deny default)` covers all socket
//!   families (the `(allow network*)` allow is dropped in
//!   [`seatbelt.rs:177`]). The TCP case here trips that same
//!   deny-default; the broader UDP / raw-socket coverage is a
//!   property of Seatbelt's deny model rather than something this
//!   test specifically pins.
//! - **Linux landlock V4** — `AccessNet::from_all(V4)` declared
//!   via `handle_access` with no `NetPort` allows. Landlock V4's
//!   net-access surface is BindTcp + ConnectTcp ONLY; UDP /
//!   `SOCK_DGRAM` / raw / AF_PACKET / DNS-via-UDP go through this
//!   sandbox UNDENIED. Closing that gap is **Phase 46.1.1's
//!   seccomp-bpf layer**; the UDP / raw-socket runtime test
//!   ships alongside that phase.
//!
//! Both platforms agree on the TCP shape: a TCP connect to any
//! host — including the loopback adapter — goes to the deny path.
//!
//! [`seatbelt.rs:177`]: ../../../../../../../lpm-dev/rust-client/crates/lpm-sandbox/src/seatbelt.rs#L177
//!
//! Filesystem-write denial is **not** in scope here. The sibling
//! workflow test [`sandbox_filesystem_denial.rs`] pins that
//! contract on the same install pipeline; this file is its
//! parallel for the network dimension.
//!
//! ## What this proves
//!
//! Per the locked Phase 46.1 deliverable #2 (in the design note),
//! two end-to-end cases pinned in the same file (shared fixture):
//!
//! 1. **Primary case** — synthetic package's `postinstall: "node
//!    install.js"` attempts `http.get(MOCK_URL)` against a wiremock
//!    mock-registry URL. Three assertions:
//!    1. The install output carries the OS-level sandbox-denial
//!       signal in stderr/stdout (`EPERM` / `EACCES` /
//!       `EHOSTUNREACH` / `ENETUNREACH` / "operation not permitted"),
//!       proving the SANDBOX denied the connect — not some other
//!       failure mode upstream.
//!    2. `.lpm-built` marker absent for the synthetic dep, proving
//!       the build pipeline observed the script's non-zero exit.
//!    3. `mock.received_requests()` is empty, proving the connect
//!       was denied at the kernel/sandbox boundary BEFORE the
//!       packet ever left the box.
//!
//! 2. **Loopback-target case** — same shape, but the mock binds
//!    explicitly to `127.0.0.1` and the test attempts to connect
//!    to that loopback. Pins the Q1 decision (no loopback
//!    exemption) at runtime, not just in the rendered profile —
//!    a future regression that adds a loopback carve-out trips this
//!    case while the primary one stays green.
//!
//! Both cases run under `--policy=allow` to bypass the triage gate
//! and isolate the test to sandbox enforcement (same approach the
//! fs-denial sibling uses).
//!
//! ## Why this lives outside `lpm-audit-corpus`
//!
//! The hermetic audit corpus (`crates/lpm-audit-corpus/src/main.rs`
//! `run_hermetic` @ ~line 747) classifies fixtures through
//! [`lpm_security::classify_script`] static analysis — it never
//! invokes `lpm-sandbox`, never spawns a child, never touches
//! Seatbelt or landlock. Changes to `seatbelt.rs:177` or
//! `linux.rs`'s ABI bump cannot move a hermetic outcome. The
//! enforcement-contract gate therefore lives at the runtime
//! integration-test layer (this file), not in the advisor layer
//! (per the locked Q3 methodology).

mod support;

use std::path::PathBuf;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

// ─── Test constants ────────────────────────────────────────────────────

/// Primary-case dep. Distinct names so two `lpm install` invocations
/// in the same test process can't collide on the per-package
/// `.lpm-built` marker check.
const PRIMARY_DEP_NAME: &str = "synthetic-net-denial-primary";
const LOOPBACK_DEP_NAME: &str = "synthetic-net-denial-loopback";
const DEP_VERSION: &str = "1.0.0";

/// The lifecycle script body that attempts outbound TCP. Reads
/// `LPM_TEST_TARGET_URL` from the env and tries one `http.get`. No
/// try/catch: a sandbox denial throws (EPERM / EACCES /
/// ECONNREFUSED-via-denial / similar), the node process exits
/// non-zero, the install pipeline records the failure, and
/// `.lpm-built` is NOT written.
///
/// The env var name is unique to this test — it doesn't match any
/// of the `*_SECRET`, `*_PASSWORD`, `*_KEY`, `*_PRIVATE_KEY` strip
/// patterns or the explicit token list at `rebuild.rs:93-104`, so
/// it survives `build_sanitized_env` unchanged. Same precedent as
/// `LPM_TEST_FORBIDDEN_PATH` in [`sandbox_filesystem_denial.rs`].
///
/// Why HTTP and not raw `net.Socket`: Node's `http.get` routes
/// through `net.Socket.connect()` under the hood, so the failure
/// signal is identical — but `http.get` is the canonical "outbound
/// network attempt" shape every lifecycle script in the wild uses
/// (prebuild downloaders, telemetry, browser fetchers). Pinning
/// the test on the user-facing API makes regression failures
/// easier to interpret.
///
/// The `await new Promise(...)` shape converts node's async
/// callback into a synchronously-awaited error so the script
/// exits non-zero ONLY when the connect actually fails — without
/// it, the event loop could drain before the `.on('error')` fires
/// and node would exit 0 with the error swallowed.
const INSTALL_JS_BODY: &[u8] = br#"
const http = require('http');
const url = process.env.LPM_TEST_TARGET_URL;
if (!url) {
    console.error('LPM_TEST_TARGET_URL unset; test harness misconfigured');
    process.exit(2);
}
async function attemptConnect() {
    return await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
            // We reached the mock. The sandbox FAILED to deny --
            // bubble that as a distinct error message so the test
            // can tell "succeeded" apart from "denied" in stderr.
            res.resume();
            reject(new Error('UNEXPECTED_HTTP_SUCCESS to ' + url));
        });
        req.setTimeout(5000, () => {
            req.destroy(new Error('timeout'));
        });
        req.on('error', (err) => reject(err));
    });
}
attemptConnect().catch((err) => {
    // Surface the sandbox-denial signal on stderr so the workflow
    // assertion can grep for EPERM / EACCES / EHOSTUNREACH /
    // ENETUNREACH / "operation not permitted". Node's http error
    // path carries `err.code` (the errno) and `err.message` (the
    // human-readable line) -- emit BOTH so either form trips the
    // assertion.
    console.error('connect-failed: code=' + (err.code || '') + ' message=' + (err.message || ''));
    process.exit(1);
});
"#;

// ─── Fixture builders ──────────────────────────────────────────────────

/// Build a tarball whose `postinstall` runs `node install.js`. The
/// `node install.js` form is classified as `Amber` (reserved
/// binary-fetcher basename) by L1, but the test runs under
/// `--policy=allow` so the trust gate is bypassed — every scripted
/// package executes regardless of tier. That isolates the test to
/// "sandbox enforcement at install time," independent of the
/// triage gate.
fn build_net_denial_tarball(dep_name: &str) -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": dep_name,
        "version": DEP_VERSION,
        "scripts": {
            "postinstall": "node install.js",
        }
    });
    make_tarball_from_pkg_json(pkg_json, &[("install.js", INSTALL_JS_BODY)])
}

/// Project manifest depending on the synthetic dep. No
/// `scriptPolicy` setting — the test passes `--policy=allow` on the
/// CLI for the same effect with the additional guarantee that
/// `auto_build_attempted` widens (the Allow policy alone fires
/// auto-build per Phase 57).
fn project_manifest(dep_name: &str) -> String {
    format!(
        r#"{{
    "name": "sandbox-net-denial-fixture-{dep_name}",
    "version": "1.0.0",
    "dependencies": {{
        "{dep_name}": "^{DEP_VERSION}"
    }}
}}
"#
    )
}

/// Mount metadata + tarball for the synthetic dep on the mock
/// registry. Same shape as `triage_install_lifecycle.rs` and
/// `sandbox_filesystem_denial.rs`: per-package metadata + batch
/// metadata. `time[version]` is far in the past so the L3 cooldown
/// gate doesn't fire — the test is pinned on sandbox enforcement,
/// not cooldown side effects.
async fn mount_net_denial_dep(mock: &MockRegistry, dep_name: &str, tarball: &[u8]) {
    mock.with_package(dep_name, DEP_VERSION, tarball).await;
    let tarball_url = format!("{}/tarballs/{dep_name}-{DEP_VERSION}.tgz", mock.url());
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

/// Path to the build-pipeline `.lpm-built` marker for the synthetic
/// dep. Written ONLY when the lifecycle script exits 0; absence
/// after a sandbox denial is the proof that the build pipeline saw
/// the failure and refused to mint a success marker.
fn lpm_built_marker(project: &TempProject, dep_name: &str) -> PathBuf {
    let safe = dep_name.replace(['/', '\\'], "+");
    project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{DEP_VERSION}"))
        .join(".lpm-built")
}

/// Strip ANSI color codes so assertions don't fight terminal
/// styling. Same helper shape as `sandbox_filesystem_denial.rs`
/// and `rebuild.rs`.
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

/// `true` if `node` is on PATH. The synthetic postinstall is `node
/// install.js`, so without node we can't exercise the spawn path
/// at all — soft-pass the test rather than fail on environment.
fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Shared assertions block. Phase 46.1 deliverable #2 pins three
/// assertions per case, plus the soft-fail contract; collected
/// here so the primary and loopback-target cases stay in lock-
/// step. A regression that diverges them would be a contract bug.
async fn assert_network_denied(
    mock: &MockRegistry,
    project: &TempProject,
    dep_name: &str,
    target_url: &str,
    case_label: &str,
) {
    let out = lpm_with_registry(project, &mock.url())
        // `--policy=allow` bypasses the triage gate so the amber
        // tier doesn't block execution — the test isolates SANDBOX
        // enforcement from TRIAGE gating. Allow also fires auto-
        // build automatically (Phase 57), so we don't need
        // `--auto-build` to widen the rebuild path.
        .args(["install", "--policy=allow"])
        // Phase 46.1 rework (2026-05-11): network denial is opt-in
        // (see `phase46-DX.md` and the matrix's strict-sandbox row).
        // This test asserts the STRICT path works, so it must opt
        // in explicitly. Without the env var, the install would use
        // `mode = "default"` and the assertion that the mock
        // received zero requests would fail (legitimately —
        // default mode lets the postinstall reach the mock).
        .env("LPM_STRICT_SANDBOX", "1")
        .env("LPM_TEST_TARGET_URL", target_url)
        .output()
        .expect("spawn lpm install");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));

    // ── Assertion 0: install exit code 0 (soft-fail contract). ──
    //
    // Auto-build failures wrap in a soft `output::warn("Auto-build
    // failed: ...")` (`install.rs:6920`) so the install exit code
    // stays 0 even when a lifecycle script fails. This test pins
    // the same contract for the network-denial path — a future
    // change that turns auto-build failures into hard install
    // exits would surface here. If you intentionally tighten the
    // contract, update both this test AND
    // `sandbox_filesystem_denial.rs`'s Assertion 0 in the same
    // commit so they stay aligned.
    assert!(
        out.status.success(),
        "[{case_label}] install exit code MUST be 0 under the current soft-fail contract — \
         auto-build failures surface as warnings + per-package lines, not hard fails. \
         Got: {:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        out.status,
    );

    // ── Assertion 1: install surfaces the failure truthfully. ──
    //
    // Two layers must each acknowledge the failure for the test
    // to credit it:
    //
    //   (a) OS-level sandbox denial signal in node's stderr.
    //       macOS Seatbelt: `EPERM` (operation not permitted).
    //       Linux landlock V4: `EACCES` (the AccessNet handler with
    //       no NetPort allow rule default-denies bind/connect with
    //       EACCES). Some OS / libc combinations surface the same
    //       denial as `EHOSTUNREACH` / `ENETUNREACH`; treat any of
    //       those as a credit.
    //   (b) Install-pipeline-level acknowledgement: a per-package
    //       "postinstall failed" surface or an aggregate "Auto-
    //       build failed" / "package(s) failed to build" line.
    //
    // Requiring BOTH catches two distinct regressions:
    //   - (a) only: sandbox denied but install reported success →
    //     user has no signal the package needs review.
    //   - (b) only: install reported failure but cause was not
    //     sandbox enforcement → could be transient network,
    //     OOM, etc. — test would give false confidence in
    //     sandbox containment.
    let combined = format!("{stderr}\n{stdout}");
    let signals_sandbox_denial = combined.contains("EPERM")
        || combined.contains("EACCES")
        || combined.contains("EHOSTUNREACH")
        || combined.contains("ENETUNREACH")
        || combined.contains("operation not permitted")
        || combined.contains("Operation not permitted")
        || combined.contains("permission denied")
        || combined.contains("Permission denied");
    assert!(
        signals_sandbox_denial,
        "[{case_label}] install output must contain the OS-level sandbox-denial signal \
         (EPERM / EACCES / EHOSTUNREACH / ENETUNREACH / 'operation not permitted' / \
         'permission denied'). Without it, the script failure could have any cause; \
         this test is asserting SANDBOX enforcement of outbound network \
         specifically.\nstderr:\n{stderr}\nstdout:\n{stdout}"
    );
    let signals_install_acknowledgement = combined.contains("postinstall failed")
        || combined.contains("Auto-build failed")
        || combined.contains("failed to build");
    assert!(
        signals_install_acknowledgement,
        "[{case_label}] install must observe the script failure and surface it in \
         user-facing output (per-package 'postinstall failed' line OR aggregate \
         'Auto-build failed' / 'failed to build'). A silent success here is a contract \
         regression — the user would have no signal the package needs review.\n\
         stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    // ── Assertion 2: `.lpm-built` marker is absent. ──
    //
    // The marker is written by the build pipeline ONLY on a
    // successful (exit 0) lifecycle-script spawn. A sandbox-denied
    // connect inside install.js bubbles up as a non-zero process
    // exit → no marker. If the marker exists, either the sandbox
    // failed to deny (regression), or the build pipeline wrote the
    // marker without observing the script's exit code (a different,
    // equally bad regression).
    let marker = lpm_built_marker(project, dep_name);
    assert!(
        !marker.exists(),
        "[{case_label}] .lpm-built marker MUST be absent after a sandbox-denied \
         lifecycle script; found at {}\nstderr:\n{stderr}",
        marker.display(),
    );

    // ── Assertion 3: mock received zero requests. ──
    //
    // The strongest signal: the wiremock server should never have
    // seen the request. The sandbox denied connect() at the kernel
    // boundary, so the TCP packet never left the box, and the mock
    // recorded no incoming traffic. If `received_requests` returns
    // a non-empty list, the sandbox bypassed denial — same level
    // of severity as the "forbidden file exists" assertion in the
    // fs-denial sibling.
    //
    // `received_requests()` returns `Option<Vec<_>>` — `None` only
    // when request-recording is explicitly disabled at build time,
    // which `MockRegistry::start` does not do. Unwrap with an
    // expect so a future change to MockRegistry that disables
    // recording surfaces as a clear test-side error rather than a
    // silent pass.
    let received = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request recording enabled");
    // The install pipeline DOES make legitimate requests to the
    // mock (metadata + tarball fetch). Filter those out — we only
    // care about whether the sandboxed lifecycle script reached
    // the registry. Specifically: the registry path the synthetic
    // script targets is the root `/` of the mock (the test passes
    // `mock.url()` directly as LPM_TEST_TARGET_URL). The metadata
    // / tarball paths the install pipeline uses are well-known
    // sub-paths under `/`.
    let sandboxed_attempts: Vec<_> = received
        .iter()
        .filter(|r| {
            let p = r.url.path();
            // Exact root-path match: the synthetic script GETs
            // `mock.url()` (no trailing path), which presents as
            // path `/`. Filtering by exact path keeps legitimate
            // install-pipeline traffic (metadata + tarball under
            // sub-paths) out of the count.
            p == "/" || p.is_empty()
        })
        .collect();
    assert!(
        sandboxed_attempts.is_empty(),
        "[{case_label}] SANDBOX BYPASS: the lifecycle script reached the mock registry \
         despite the sandbox's outbound network deny. This is a real security \
         regression. requests:\n{:#?}\nstderr:\n{stderr}",
        sandboxed_attempts,
    );
}

// ─── Contract — outbound network denial at install time ──────────────

/// Primary case: synthetic package's postinstall attempts an HTTP
/// GET to a wiremock mock-registry URL (which binds to 127.0.0.1
/// by wiremock default). The sandbox MUST deny the connect, the
/// build pipeline MUST observe the script failure, the
/// `.lpm-built` marker MUST be absent, AND the mock MUST receive
/// zero requests for the root path.
///
/// Unix-only for the same reason `triage_install_lifecycle.rs`
/// and `sandbox_filesystem_denial.rs` guard their mock setup
/// behind `#[cfg(unix)]`: the sandbox + lifecycle-script pipeline
/// doesn't ship a Windows backend in Phase 46.1 (Windows is
/// deferred to a follow-up phase per the design note).
#[cfg(unix)]
#[tokio::test]
async fn postinstall_outbound_connect_is_denied_marker_absent_mock_silent() {
    if !node_available() {
        // Soft-pass: this test is fundamentally about a Node-
        // spawned script hitting the sandbox. Without `node` on
        // PATH the spawn step never runs and there's nothing to
        // gate. Mirroring the `sandbox_filesystem_denial.rs` +
        // `rebuild.rs` precedent for the same condition.
        eprintln!("skipping: node not on PATH");
        return;
    }

    let mock = MockRegistry::start().await;
    let tarball = build_net_denial_tarball(PRIMARY_DEP_NAME);
    mount_net_denial_dep(&mock, PRIMARY_DEP_NAME, &tarball).await;

    let project = TempProject::empty(&project_manifest(PRIMARY_DEP_NAME));

    // Primary target: the mock's URL as wiremock surfaces it.
    // wiremock binds to `127.0.0.1:<random>` by default — see
    // `MockServer::start()` behaviour. The loopback-target case
    // below pins this binding explicitly to lock the Q1 contract
    // ("no loopback exemption") regardless of any future default
    // change.
    let target_url = mock.url();
    assert_network_denied(&mock, &project, PRIMARY_DEP_NAME, &target_url, "primary").await;
}

/// Loopback-target case: same install / postinstall shape, but
/// the mock binds explicitly to `127.0.0.1` via a pre-bound
/// `TcpListener`. Pins the Q1 decision (no loopback exemption) at
/// runtime, not just in profile rendering — a future regression
/// that re-adds `(allow network* (local ip "lo0"))` on macOS or a
/// `NetPort::new(port, ConnectTcp)` for loopback on Linux would
/// keep the primary case green (which uses an arbitrary random
/// port) while turning this case green-too. Both are required to
/// hold; if either silently flips, the contract is broken.
///
/// Note: in the current implementation wiremock's default
/// `MockServer::start()` ALSO binds to `127.0.0.1`, so the two
/// cases overlap at the IP-address level. The distinction this
/// case makes is *explicitness*: the listener binding is locked
/// to loopback BY US, so even if wiremock changes its default
/// later, this case still asserts what it claims to assert.
#[cfg(unix)]
#[tokio::test]
async fn postinstall_loopback_connect_is_denied_no_loopback_exemption() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }

    // Bind explicitly to 127.0.0.1:0 (random ephemeral port).
    // The pre-bound TcpListener flows into `MockServer::builder()
    // .listener(...)` so the mock binds to OUR explicit loopback
    // socket, not whatever wiremock's default happens to be.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind explicit loopback for the no-loopback-exemption case");
    let listener_addr = listener.local_addr().expect("local_addr");
    assert!(
        listener_addr.ip().is_loopback(),
        "test invariant: listener must be on the loopback adapter, got {listener_addr}",
    );

    let server = wiremock::MockServer::builder()
        .listener(listener)
        .start()
        .await;
    let mock = MockRegistry::from_server(server);
    let tarball = build_net_denial_tarball(LOOPBACK_DEP_NAME);
    mount_net_denial_dep(&mock, LOOPBACK_DEP_NAME, &tarball).await;

    let project = TempProject::empty(&project_manifest(LOOPBACK_DEP_NAME));

    let target_url = format!("http://127.0.0.1:{}", listener_addr.port());
    assert_network_denied(&mock, &project, LOOPBACK_DEP_NAME, &target_url, "loopback").await;
}
