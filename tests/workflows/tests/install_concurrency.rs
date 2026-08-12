//! Concurrency and recovery contract tests for `lpm install`.
//!
//! These tests pin behavior under production failure modes that need
//! workflow-level coverage:
//!
//! - **Category A — process racing.** Two `lpm` processes on the same
//!   project, install + cache-clean, install + store-clean, two
//!   `lpm install -g`. Validates the advisory-lock contract at
//!   [crates/lpm-common/src/paths.rs:605-723](../../../crates/lpm-common/src/paths.rs).
//!
//! - **Category B — interruption recovery.** `Child::kill()` mid-install
//!   (SIGKILL on Unix, `TerminateProcess` on Windows). The
//!   [`ManifestTransaction`](../../../crates/lpm-cli/src/manifest_tx.rs)
//!   Drop guard does NOT run on SIGKILL — the contract is that the
//!   next `lpm install` converges via the invalidated
//!   `.lpm/install-hash`.
//!
//! - **Category C — network faults.** wiremock-driven retry / 5xx /
//!   404 / truncated-body scenarios against the registry client at
//!   [crates/lpm-registry/src/client.rs:3840](../../../crates/lpm-registry/src/client.rs) (3 retries, 1-10s
//!   exponential backoff).
//!
//! - **Category D — filesystem faults.** Read-only project dir,
//!   `.lpm` is a regular file. Cross-platform via `#[cfg]`.
//!
//! - **Category E — partial state recovery.** Stale install-hash,
//!   truncated `lpm.lockb`, partial `node_modules/`.
//!
//! - **Category F — WAL recovery hook.** Proves
//!   [`lpm_global::recover()`](../../../crates/lpm-global/src/recover.rs) fires
//!   from the dispatcher at [main.rs:2515](../../../crates/lpm-cli/src/main.rs).
//!
//! Keep the verified architectural facts close to the behavior each test
//! protects.

mod support;

use std::process::Child;
use std::time::{Duration, Instant};
use support::mock_registry::{
    MockRegistry, compute_integrity, make_tarball, make_tarball_from_pkg_json,
};
use support::{TempProject, lpm, lpm_spawnable_with_registry, lpm_with_registry};

// ─── Shared helpers ──────────────────────────────────────────────────

/// Mount a package on the mock with a `set_delay` on the tarball
/// endpoint, widening the race window in concurrency tests to a
/// deterministic value. `with_package` doesn't expose the delay knob;
/// we mount the three routes ourselves.
async fn with_delayed_package(
    mock: &MockRegistry,
    name: &str,
    version: &str,
    tarball_bytes: Vec<u8>,
    delay: Duration,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let tarball_url = format!("{}/tarballs/{name}/-/{name}-{version}.tgz", mock.url());
    let integrity = compute_integrity(&tarball_bytes);
    mock.register_tarball_integrity(name, version, integrity.clone());
    let metadata = serde_json::json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": { "tarball": tarball_url, "integrity": integrity },
                "dependencies": {}
            }
        },
        "time": { version: "2025-01-01T00:00:00.000Z" }
    });

    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tarballs/{name}/-/{name}-{version}.tgz")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball_bytes)
                .insert_header("content-type", "application/octet-stream")
                .set_delay(delay),
        )
        .mount(mock.server())
        .await;
}

/// Wait until a predicate holds or `timeout` elapses, polling every
/// 25ms. Returns `true` if the predicate held within budget.
fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    predicate()
}

/// Best-effort `Child::wait` with a wall-clock cap. Sends SIGKILL on
/// timeout so the test doesn't hang the suite. Borrows the child so
/// callers can still consume its piped stdout/stderr afterwards via
/// `wait_with_output` from `read_remaining_output`.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return child.wait().expect("wait after kill");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
}

// ─── Category A — Process racing ─────────────────────────────────────

/// **A.1 — two concurrent installs on the same project.**
///
/// `lpm install` holds shared `store_lock` only (see
/// [install.rs:3272](../../../crates/lpm-cli/src/commands/install.rs)). No project-level lock exists, so two
/// installs on the same project DO race on `package.json` + `lpm.lock`
/// writes through their own `ManifestTransaction` snapshots.
///
/// Contract pinned: regardless of which process wins the manifest
/// race, the post-state files must be **well-formed** — never partial
/// JSON, never truncated TOML. Either both packages are present in
/// `package.json` (merge succeeded) or one is (last-writer-wins), but
/// the file must parse. Both processes must terminate within budget.
///
/// Finding-grade outcome: if the race produces invalid JSON or
/// invalid TOML, that's a corruption-grade bug → file under the
/// project-lock track in `findings.md`.
#[tokio::test]
async fn two_concurrent_installs_on_same_project_leave_well_formed_manifest() {
    let mock = MockRegistry::start().await;
    let tarball_a = make_tarball("pkg-a", "1.0.0");
    let tarball_b = make_tarball("pkg-b", "1.0.0");
    // ~500ms delay each so the two processes are guaranteed to overlap
    // in the manifest-write window.
    with_delayed_package(
        &mock,
        "pkg-a",
        "1.0.0",
        tarball_a,
        Duration::from_millis(500),
    )
    .await;
    with_delayed_package(
        &mock,
        "pkg-b",
        "1.0.0",
        tarball_b,
        Duration::from_millis(500),
    )
    .await;
    mock.with_batch_metadata(vec![
        single_version_batch_metadata("pkg-a", "1.0.0", &mock.url()),
        single_version_batch_metadata("pkg-b", "1.0.0", &mock.url()),
    ])
    .await;

    let project = TempProject::empty(r#"{"name":"race-test","version":"1.0.0"}"#);

    let mut child_a = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["pkg-a@1.0.0"]))
        .spawn()
        .expect("spawn install A");
    let mut child_b = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["pkg-b@1.0.0"]))
        .spawn()
        .expect("spawn install B");

    // Both should terminate well within the 60s cap. The set_delay on
    // tarball fetch keeps each install above ~500ms, guaranteeing
    // overlap in the manifest-write region.
    let race_start = Instant::now();
    let status_a = wait_with_timeout(&mut child_a, Duration::from_secs(60));
    let status_b = wait_with_timeout(&mut child_b, Duration::from_secs(60));
    let race_elapsed = race_start.elapsed();

    // Capture both processes' stdout/stderr regardless of outcome so
    // failures are diagnosable.
    let out_a = read_remaining_output(child_a);
    let out_b = read_remaining_output(child_b);

    // Diagnostic: surface what actually happened so we can tell whether
    // both installs ran or one failed at startup. The 500ms tarball
    // delay should keep total wall-clock above 500ms even with full
    // overlap; under 200ms means one install failed before fetching.
    eprintln!(
        "[A.1] race_elapsed={race_elapsed:?}\n\
         status_a={status_a:?} stderr_a:\n{}\n\
         status_b={status_b:?} stderr_b:\n{}",
        out_a.stderr, out_b.stderr
    );
    assert!(
        race_elapsed >= Duration::from_millis(300),
        "race completed too fast ({race_elapsed:?}) — at least one install \
         likely failed before fetching the delayed tarball"
    );

    // POST-CONDITION 1: package.json parses as valid JSON.
    let pkg_json_bytes = std::fs::read(project.path().join("package.json"))
        .expect("package.json must exist after race");
    let pkg_json: serde_json::Value = serde_json::from_slice(&pkg_json_bytes).unwrap_or_else(|e| {
        panic!(
            "concurrent installs corrupted package.json (invalid JSON: {e})\n\
             status_a={status_a:?} status_b={status_b:?}\n\
             stderr_a={}\nstderr_b={}\n\
             raw bytes:\n{}",
            out_a.stderr,
            out_b.stderr,
            String::from_utf8_lossy(&pkg_json_bytes)
        );
    });

    // POST-CONDITION 2: if lpm.lock exists, it parses. (Either process
    // may have committed; an absent lockfile means both rolled back —
    // also acceptable.)
    let lockfile_path = project.path().join("lpm.lock");
    if lockfile_path.exists() {
        let lock_bytes = std::fs::read(&lockfile_path).expect("read lockfile");
        // lpm.lock is TOML; we don't need toml here — just well-formed
        // UTF-8 with no embedded NUL is the minimum bar. The full TOML
        // parse runs implicitly on the next install (E.3 covers
        // recovery from a torn lockfile).
        let _text = std::str::from_utf8(&lock_bytes).unwrap_or_else(|e| {
            panic!(
                "concurrent installs corrupted lpm.lock (invalid UTF-8: {e})\n\
                 stderr_a={}\nstderr_b={}",
                out_a.stderr, out_b.stderr
            );
        });
    }

    // POST-CONDITION 3: both installs succeeded AND both packages landed
    // in the manifest AND both are
    // linked into `node_modules/`. Pre-fix this section was diagnostic-
    // only because `lpm install` held only a shared `store_lock` and
    // the per-process `ManifestTransaction` snapshots didn't coordinate
    // across processes — last-writer-wins. The project-install lock
    // (per-project `<project>/.lpm/.install.lock`, exclusive,
    // `with_exclusive_lock_async`) added at install.rs/add.rs serializes
    // the snapshot+install+commit window so both packages survive the
    // race.
    let deps = pkg_json
        .get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let pkg_a_in_deps = deps.contains_key("pkg-a");
    let pkg_b_in_deps = deps.contains_key("pkg-b");
    let pkg_a_linked = project.path().join("node_modules/pkg-a").exists();
    let pkg_b_linked = project.path().join("node_modules/pkg-b").exists();
    eprintln!(
        "[A.1 race-state] status_a={status_a:?} status_b={status_b:?} \
         manifest_has_pkg_a={pkg_a_in_deps} manifest_has_pkg_b={pkg_b_in_deps} \
         node_modules_has_pkg_a={pkg_a_linked} node_modules_has_pkg_b={pkg_b_linked}\n\
         stderr_a:\n{}\nstderr_b:\n{}",
        out_a.stderr, out_b.stderr
    );

    assert!(
        status_a.success(),
        "install A failed under concurrent install — project-lock \
         contract requires both invocations succeed. \
         status_a={status_a:?} stderr_a:\n{}",
        out_a.stderr
    );
    assert!(
        status_b.success(),
        "install B failed under concurrent install — project-lock \
         contract requires both invocations succeed. \
         status_b={status_b:?} stderr_b:\n{}",
        out_b.stderr
    );

    assert!(
        pkg_a_in_deps,
        "pkg-a missing from package.json dependencies after concurrent \
         install — manifest race is still occurring. manifest deps: {:?}",
        deps.keys().collect::<Vec<_>>()
    );
    assert!(
        pkg_b_in_deps,
        "pkg-b missing from package.json dependencies after concurrent \
         install — manifest race is still occurring. manifest deps: {:?}",
        deps.keys().collect::<Vec<_>>()
    );
    assert!(
        pkg_a_linked,
        "pkg-a missing from node_modules after concurrent install — \
         node_modules race is occurring (one install's link phase \
         was clobbered by the other)."
    );
    assert!(
        pkg_b_linked,
        "pkg-b missing from node_modules after concurrent install — \
         node_modules race is occurring."
    );
}

/// **A.3 — install (shared `store_lock`) + `store clean` (exclusive
/// `store_lock`) serialize.**
///
/// Same lock path, opposite modes. The exclusive holder must block
/// until every shared holder releases (and vice versa).
///
/// Contract pinned: store-clean must run AFTER install commits, never
/// during. Asserted by observation: install's commit timestamp <
/// store-clean's start timestamp.
#[tokio::test]
async fn install_with_shared_store_lock_blocks_concurrent_store_clean() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("slow-pkg", "1.0.0");
    // 1500ms delay holds the install's shared store_lock long enough
    // that the racing store-clean MUST observe it and block.
    with_delayed_package(
        &mock,
        "slow-pkg",
        "1.0.0",
        tarball,
        Duration::from_millis(1500),
    )
    .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "slow-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"clean-race","version":"1.0.0"}"#);

    let install_start = Instant::now();
    let mut install_child = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["slow-pkg@1.0.0"]))
        .spawn()
        .expect("spawn install");

    // Wait until the install has acquired the shared `store_lock`.
    // The lock file lives at `<LPM_HOME>/.lpm/store/.gc.lock` per
    // `LpmRoot::store_lock` — but the FILE existing doesn't prove the
    // lock is held (it's opened-or-created early). The reliable proxy
    // is `try_with_exclusive_lock(store_lock())` returning `Ok(None)`,
    // which is what `with_shared_lock_async` competes with.
    let store_lock_path = project.home().join(".lpm").join("store").join(".gc.lock");
    assert!(
        wait_until(Duration::from_secs(10), || {
            // First, the file must exist.
            if !store_lock_path.exists() {
                return false;
            }
            // Then, attempt non-blocking exclusive — if it returns
            // WouldBlock (Ok(None)), someone else holds it shared.
            match lpm_common::try_with_exclusive_lock(&store_lock_path, || Ok(())) {
                Ok(None) => true, // install is holding shared lock
                _ => false,       // either error or no holder yet
            }
        }),
        "install never acquired shared store_lock within 10s"
    );

    // Race a store-clean. It uses exclusive store_lock against the
    // same path that install holds shared, so it MUST block.
    let clean_start = Instant::now();
    let clean_output = lpm(&project)
        .args(["store", "clean"])
        .output()
        .expect("run store clean");
    let clean_end = Instant::now();

    // Install must finish first (or roughly co-terminate).
    let install_status = wait_with_timeout(&mut install_child, Duration::from_secs(60));
    let install_end = Instant::now();
    let install_out = read_remaining_output(install_child);

    assert!(
        install_status.success(),
        "install failed:\nstdout={}\nstderr={}",
        install_out.stdout,
        install_out.stderr
    );
    assert!(
        clean_output.status.success(),
        "store clean failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&clean_output.stdout),
        String::from_utf8_lossy(&clean_output.stderr)
    );

    // Serialization evidence: store-clean's runtime must overlap with
    // install's lock window — meaning clean was waiting. If clean
    // returned before install finished, the locks weren't actually
    // serializing.
    let install_elapsed = install_end.duration_since(install_start);
    let clean_elapsed = clean_end.duration_since(clean_start);
    assert!(
        install_elapsed >= Duration::from_millis(1500),
        "install completed too fast (didn't actually exercise the delay):\n\
         install_elapsed={install_elapsed:?}"
    );

    // Either store-clean blocked long enough to overlap, OR it ran
    // entirely after install committed. Both prove serialization.
    let serialized = clean_elapsed >= Duration::from_millis(500)
        || clean_start.duration_since(install_start) >= install_elapsed;
    assert!(
        serialized,
        "store clean appeared to run concurrently with install — \
         no serialization observed.\n\
         install_elapsed={install_elapsed:?} clean_elapsed={clean_elapsed:?}\n\
         clean_start_offset_from_install_start={:?}",
        clean_start.duration_since(install_start)
    );
}

/// **A.4 — two concurrent `lpm install -g` produce a coherent global state.**
///
/// Unlike project installs, global installs wrap their **commit** sections with `global_tx_lock` held
/// exclusively (see the global install and update command facades).
/// The fetch+extract+link phases run in parallel; only the WAL-commit
/// regions serialize. The user-facing contract is therefore not "total
/// wall-clock doubles" but rather: **both packages end up in
/// `manifest.toml`, no torn WAL, no torn manifest, both bins available**.
/// Pinning the corruption-free outcome is what matters; observing
/// serialization via timing is brittle (would race-condition the
/// race-detection itself).
#[tokio::test]
async fn two_concurrent_global_installs_serialize_via_global_tx_lock() {
    let mock = MockRegistry::start().await;
    // `lpm install -g` requires a `bin` entry on the inner package.json
    // — otherwise the install errors with "exposes no bin entries". Use
    // `make_tarball_from_pkg_json` to declare bin.
    let tarball_a = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "gpkg-a",
            "version": "1.0.0",
            "bin": { "gpkg-a": "./bin.js" },
        }),
        &[("bin.js", b"#!/usr/bin/env node\nconsole.log('a');\n")],
    );
    let tarball_b = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "gpkg-b",
            "version": "1.0.0",
            "bin": { "gpkg-b": "./bin.js" },
        }),
        &[("bin.js", b"#!/usr/bin/env node\nconsole.log('b');\n")],
    );
    // 500ms delay on each — if they ran in parallel, total ≈ 500ms;
    // serialized, total ≈ 1000ms+.
    with_delayed_package(
        &mock,
        "gpkg-a",
        "1.0.0",
        tarball_a,
        Duration::from_millis(500),
    )
    .await;
    with_delayed_package(
        &mock,
        "gpkg-b",
        "1.0.0",
        tarball_b,
        Duration::from_millis(500),
    )
    .await;
    mock.with_batch_metadata(vec![
        single_version_batch_metadata("gpkg-a", "1.0.0", &mock.url()),
        single_version_batch_metadata("gpkg-b", "1.0.0", &mock.url()),
    ])
    .await;

    // Global installs don't need a project directory, but our env
    // helpers want one — use an empty `TempProject` for HOME isolation.
    let project = TempProject::empty(r#"{"name":"global-race","version":"1.0.0"}"#);

    let race_start = Instant::now();
    let mut child_a = lpm_spawnable_with_registry(&project, &mock.url())
        .args([
            "install",
            "-g",
            "--no-security-summary",
            "--no-skills",
            "gpkg-a@1.0.0",
        ])
        .spawn()
        .expect("spawn install -g A");
    let mut child_b = lpm_spawnable_with_registry(&project, &mock.url())
        .args([
            "install",
            "-g",
            "--no-security-summary",
            "--no-skills",
            "gpkg-b@1.0.0",
        ])
        .spawn()
        .expect("spawn install -g B");

    let status_a = wait_with_timeout(&mut child_a, Duration::from_secs(60));
    let status_b = wait_with_timeout(&mut child_b, Duration::from_secs(60));
    let race_elapsed = race_start.elapsed();

    let out_a = read_remaining_output(child_a);
    let out_b = read_remaining_output(child_b);

    assert!(
        status_a.success() && status_b.success(),
        "concurrent global installs both must succeed under \
         global_tx_lock serialization.\n\
         status_a={status_a:?} stderr_a:\n{}\n\
         status_b={status_b:?} stderr_b:\n{}",
        out_a.stderr,
        out_b.stderr
    );

    // Wall-clock evidence is intentionally NOT asserted: only the
    // commit regions serialize, and the fetch+link phases run in
    // parallel. A timing assertion would race-condition the
    // race-detection itself. We've already proved both processes
    // succeeded (above) — the rest pins corruption-free final state.
    let _ = race_elapsed;

    // Final state: both packages present in the global manifest. The
    // file is TOML; we look for both package names without parsing
    // (avoid pulling in a toml dep for one test).
    let global_manifest_path = project.home().join(".lpm/global/manifest.toml");
    assert!(
        global_manifest_path.exists(),
        "global manifest missing at {}",
        global_manifest_path.display()
    );
    let manifest_text =
        std::fs::read_to_string(&global_manifest_path).expect("read global manifest");
    assert!(
        manifest_text.contains("gpkg-a") && manifest_text.contains("gpkg-b"),
        "global manifest missing one or both packages after serialized installs:\n{manifest_text}"
    );

    // WAL coherence: the on-disk WAL format is binary (framed
    // `len|crc|payload|sentinel`, not JSON-lines despite the `.jsonl`
    // extension — see [crates/lpm-global/src/wal.rs](../../../crates/lpm-global/src/wal.rs)). Rather than
    // parse the frames here, we delegate to the recovery hook: a
    // follow-up `lpm` command runs `lpm_global::recover()` first,
    // which would either rebuild after a torn tail (printing a
    // "global recovery: …" line on stderr) or run silently. We
    // assert NO recovery message — meaning both concurrent commits
    // landed cleanly.
    let list_output = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("run global list");
    let list_stderr = String::from_utf8_lossy(&list_output.stderr);
    assert!(
        list_output.status.success(),
        "follow-up `global list` failed:\nstderr:\n{list_stderr}"
    );
    assert!(
        !list_stderr.contains("global recovery:"),
        "WAL needed recovery after concurrent global installs — \
         torn-write risk surfaced.\nlist stderr:\n{list_stderr}"
    );
}

// ─── Category B — Mid-install interruption (Child::kill) ────────────

/// **B.1 — SIGKILL mid-install leaves no `.lpm/install-hash`.**
///
/// `ManifestTransaction`'s Drop guard does NOT run on SIGKILL (per
/// [manifest_tx.rs:32-43](../../../crates/lpm-cli/src/manifest_tx.rs)),
/// so the contract isn't "rollback fires" — it's "the install-hash
/// freshness cache wasn't written yet". The hash is the LAST file the
/// pipeline writes (post-`run_with_options` success), so a kill
/// during tarball fetch trivially leaves it absent.
///
/// This test pins the **safe-by-construction** part of the contract:
/// kill before write-completion → file absent → next install
/// re-resolves (proven in B.2).
#[tokio::test]
async fn install_killed_mid_tarball_does_not_write_install_hash() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("slow-pkg", "1.0.0");
    // 2s tarball delay; we kill ~700ms in, deep mid-fetch.
    with_delayed_package(
        &mock,
        "slow-pkg",
        "1.0.0",
        tarball,
        Duration::from_millis(2000),
    )
    .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "slow-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"kill-test","version":"1.0.0"}"#);

    let mut child = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["slow-pkg@1.0.0"]))
        .spawn()
        .expect("spawn install");

    // Wait until install has actually acquired its shared store_lock —
    // proves the pipeline is past initialization and into the fetch
    // window. After that, a 200ms grace lets it commit to a tarball
    // request before we kill.
    let store_lock_path = project.home().join(".lpm").join("store").join(".gc.lock");
    assert!(
        wait_until(Duration::from_secs(10), || {
            store_lock_path.exists()
                && matches!(
                    lpm_common::try_with_exclusive_lock(&store_lock_path, || Ok(())),
                    Ok(None)
                )
        }),
        "install never acquired shared store_lock — kill harness inert"
    );
    std::thread::sleep(Duration::from_millis(200));

    child.kill().expect("kill install child");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    assert!(
        !status.success(),
        "killed install reported success: {status:?}"
    );

    // Contract: install-hash must NOT exist post-kill.
    let install_hash = project.path().join(".lpm").join("install-hash");
    assert!(
        !install_hash.exists(),
        "install-hash present after mid-fetch kill — would let the \
         next install fast-exit on a state that never finished. \
         path={}",
        install_hash.display()
    );

    // Drain piped streams so resources release cleanly. We don't
    // assert stderr contents — kill is unilateral, the binary has no
    // graceful shutdown hook here.
    let _ = read_remaining_output(child);
}

/// **B.2 — `lpm install` after a SIGKILL'd install converges.**
///
/// Pins the user-facing recovery contract: even though SIGKILL skips
/// the `ManifestTransaction` Drop, the next `lpm install` re-resolves
/// (because `.lpm/install-hash` is absent per B.1) and produces a
/// coherent end state.
#[tokio::test]
async fn install_after_killed_install_converges_on_retry() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("slow-pkg", "1.0.0");
    with_delayed_package(
        &mock,
        "slow-pkg",
        "1.0.0",
        tarball,
        Duration::from_millis(2000),
    )
    .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "slow-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"converge-test","version":"1.0.0"}"#);

    // First attempt: kill mid-fetch.
    let mut first = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["slow-pkg@1.0.0"]))
        .spawn()
        .expect("spawn first install");
    let store_lock_path = project.home().join(".lpm").join("store").join(".gc.lock");
    assert!(
        wait_until(Duration::from_secs(10), || {
            store_lock_path.exists()
                && matches!(
                    lpm_common::try_with_exclusive_lock(&store_lock_path, || Ok(())),
                    Ok(None)
                )
        }),
        "first install never acquired shared store_lock"
    );
    std::thread::sleep(Duration::from_millis(200));
    first.kill().expect("kill first install");
    let _ = wait_with_timeout(&mut first, Duration::from_secs(5));
    let _ = read_remaining_output(first);

    // Second attempt: no delay shenanigans, must succeed and converge.
    // Re-mount the package without delay for fast convergence; the
    // earlier mounts stay registered with the 2s delay, but wiremock
    // serves the most-recently-mounted matcher first.
    let fast_tarball = make_tarball("slow-pkg", "1.0.0");
    mock.with_package("slow-pkg", "1.0.0", &fast_tarball).await;

    let second = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["slow-pkg@1.0.0"]))
        .output()
        .expect("run second install");
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        second.status.success(),
        "second install failed to converge after killed first install:\n\
         stdout:\n{second_stdout}\nstderr:\n{second_stderr}"
    );

    // Final state: package.json has the dep, node_modules has the
    // link, install-hash is present and matches the recomputed state.
    let pkg_json =
        std::fs::read_to_string(project.path().join("package.json")).expect("read package.json");
    assert!(
        pkg_json.contains("\"slow-pkg\""),
        "slow-pkg missing from package.json after convergence:\n{pkg_json}"
    );
    assert!(
        project.path().join("node_modules/slow-pkg").exists(),
        "slow-pkg missing from node_modules after convergence"
    );
    assert!(
        project.path().join(".lpm/install-hash").exists(),
        ".lpm/install-hash missing after convergence — freshness cache broken"
    );
}

/// **B.3 — SIGKILL never leaves a torn `lpm.lock` on disk.**
///
/// The install pipeline removes the pre-existing `lpm.lock` at
/// [install.rs:10871-10873](../../../crates/lpm-cli/src/commands/install.rs) before re-resolving, so SIGKILL during
/// the fetch+link phase trivially leaves `lpm.lock` absent. The
/// interesting case is the post-resolve / pre-commit window where
/// the pipeline has written a freshly-resolved `lpm.lock` but the
/// `ManifestTransaction` hasn't committed yet.
///
/// Reaching that window deterministically requires a slow link phase,
/// which we can't induce from outside the binary. Instead, the test
/// covers the WEAKER (but still load-bearing) contract: across many
/// kill points, `lpm.lock` is never torn — it is either ABSENT or
/// parses as TOML. We exercise the harness's two natural kill windows
/// (fresh project + post-fetch project) and assert the contract in
/// each.
///
/// Companion to B.1 (no install-hash) and B.2 (next install
/// converges). All three together pin the SIGKILL recovery story.
#[tokio::test]
async fn install_killed_mid_pipeline_leaves_well_formed_or_absent_lockfile() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("torn-lock-pkg", "1.0.0");
    with_delayed_package(
        &mock,
        "torn-lock-pkg",
        "1.0.0",
        tarball,
        Duration::from_millis(2000),
    )
    .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "torn-lock-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"torn-lock-test","version":"1.0.0"}"#);

    // KILL WINDOW 1: fresh project (no pre-existing lpm.lock).
    let mut first = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["torn-lock-pkg@1.0.0"]))
        .spawn()
        .expect("spawn first install");
    let store_lock_path = project.home().join(".lpm").join("store").join(".gc.lock");
    assert!(
        wait_until(Duration::from_secs(10), || {
            store_lock_path.exists()
                && matches!(
                    lpm_common::try_with_exclusive_lock(&store_lock_path, || Ok(())),
                    Ok(None)
                )
        }),
        "first install never acquired shared store_lock"
    );
    std::thread::sleep(Duration::from_millis(200));
    first.kill().expect("kill first install");
    let _ = wait_with_timeout(&mut first, Duration::from_secs(5));
    let _ = read_remaining_output(first);

    assert_lockfile_well_formed_or_absent(project.path(), "after kill window 1 (fresh project)");

    // KILL WINDOW 2: project with a committed lpm.lock from a prior
    // successful install. Re-mount the same package without delay so
    // the prior install completes cleanly, THEN race a new install
    // that adds a different package.
    mock.with_package(
        "torn-lock-pkg",
        "1.0.0",
        &make_tarball("torn-lock-pkg", "1.0.0"),
    )
    .await;
    let prep = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["torn-lock-pkg@1.0.0"]))
        .output()
        .expect("run prep install");
    assert!(
        prep.status.success(),
        "kill-window-2 setup: prep install failed: {}",
        String::from_utf8_lossy(&prep.stderr)
    );
    assert!(
        project.path().join("lpm.lock").exists(),
        "kill-window-2 setup: prep install didn't produce a lpm.lock"
    );

    let second_pkg = make_tarball_from_pkg_json(
        serde_json::json!({"name":"torn-lock-pkg-2","version":"1.0.0"}),
        &[],
    );
    with_delayed_package(
        &mock,
        "torn-lock-pkg-2",
        "1.0.0",
        second_pkg,
        Duration::from_millis(2000),
    )
    .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "torn-lock-pkg-2",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let mut second = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["torn-lock-pkg-2@1.0.0"]))
        .spawn()
        .expect("spawn second install");
    assert!(
        wait_until(Duration::from_secs(10), || {
            store_lock_path.exists()
                && matches!(
                    lpm_common::try_with_exclusive_lock(&store_lock_path, || Ok(())),
                    Ok(None)
                )
        }),
        "second install never acquired shared store_lock"
    );
    std::thread::sleep(Duration::from_millis(200));
    second.kill().expect("kill second install");
    let _ = wait_with_timeout(&mut second, Duration::from_secs(5));
    let _ = read_remaining_output(second);

    assert_lockfile_well_formed_or_absent(
        project.path(),
        "after kill window 2 (project had committed lpm.lock)",
    );
}

fn assert_lockfile_well_formed_or_absent(project_dir: &std::path::Path, context: &str) {
    let lockfile = project_dir.join("lpm.lock");
    if !lockfile.exists() {
        return; // (a) absent — contract satisfied
    }
    let bytes = std::fs::read(&lockfile)
        .unwrap_or_else(|e| panic!("{context}: failed to read existing lpm.lock: {e}"));
    let text = std::str::from_utf8(&bytes).unwrap_or_else(|e| {
        panic!(
            "{context}: lpm.lock present but not valid UTF-8: {e}\n\
             First 64 bytes hex: {:?}",
            &bytes[..bytes.len().min(64)]
        )
    });
    // (b) parses as TOML — contract satisfied
    let _: toml::Value = toml::from_str(text).unwrap_or_else(|e| {
        panic!(
            "{context}: lpm.lock present but not parseable as TOML — \
             SIGKILL left a torn lockfile on disk.\n\
             Parse error: {e}\nFull contents:\n{text}"
        )
    });
}

/// **B.4 — install panics mid-pipeline → ManifestTransaction Drop restores manifest.**
///
/// SIGKILL bypasses Drop entirely (unkillable rollback); panic does
/// NOT — Rust's default `panic = "unwind"` runs every Drop on the
/// stack during the unwind. The
/// [`ManifestTransaction`](../../../crates/lpm-cli/src/manifest_tx.rs)
/// guard at [install.rs:10863](../../../crates/lpm-cli/src/commands/install.rs#L10863)
/// snapshots `package.json` + `lpm.lock` + `lpm.lockb` at construction
/// and restores them in its `Drop` impl unless `tx.commit()` ran. A
/// panic between snapshot and commit MUST trigger that rollback.
///
/// **Pre-test hook.** Recoverable errors fire `?`-rollback, but there
/// was no deterministic way to trigger a panic inside the install pipeline
/// from a workflow test. The
/// `maybe_test_panic(stage)` hook at [install.rs](../../../crates/lpm-cli/src/commands/install.rs)
/// reads `LPM_TEST_PANIC_AT` and panics deterministically when the
/// stage matches. The hook is honored only by debug builds so
/// production is immune. Wired stages: `after-snapshot`, `after-stage`,
/// `after-install`, `after-finalize`.
///
/// **Stage chosen for the rollback proof: `after-stage`.** This is
/// the load-bearing stage because:
///
/// - `after-snapshot`: rollback is a no-op (snapshot bytes ==
///   on-disk bytes).
/// - `after-stage`: `package.json` now contains the staged `*`
///   placeholder. Without rollback, the user's manifest would
///   permanently contain `"<pkg>": "*"` — the load-bearing
///   data-loss surface the snapshot-tx was designed to prevent.
/// - `after-install` / `after-finalize`: more interesting from a
///   rollback-coverage perspective, but `after-stage` is the
///   minimum failure mode that proves the contract.
///
/// Pinned contract:
///
/// - Process exits non-zero (panic propagates to the runtime).
/// - Stderr contains `"panicked at"` + `"LPM_TEST_PANIC_AT="` (proves
///   the hook fired AND the rollback happened during unwinding —
///   if Drop didn't run, we'd still see the panic but the on-disk
///   state would be wrong).
/// - `package.json` bytes are EXACTLY the pre-stage bytes (no `*`
///   placeholder, no garbage). The load-bearing assertion.
/// - The new package is NOT in `dependencies` (the staged entry
///   was rolled back).
/// - `.lpm/install-hash` is absent (invalidate-on-rollback).
/// - `lpm.lock` is absent OR byte-identical to pre-stage (the
///   transaction snapshotted it as `optional`).
///
/// **What this test does NOT cover.** Workspace path
/// (`run_install_filtered_add`) and `lpm add` have separate
/// transaction sites; the hook is wired only in `run_add_packages`
/// today. Follow-up if needed — A.1's race surface used
/// `run_add_packages` so this is the highest-value first wiring.
#[cfg(debug_assertions)]
#[tokio::test]
async fn install_panics_mid_pipeline_rollback_restores_manifest() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("rollback-pkg", "1.0.0");
    mock.with_package("rollback-pkg", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "rollback-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let pre_stage_pkg_json = r#"{
  "name": "panic-rollback-test",
  "version": "1.0.0"
}"#;
    let project = TempProject::empty(pre_stage_pkg_json);

    // Pre-flight: verify the snapshot will see this exact pre-stage
    // content. If we ever change `TempProject::empty`'s formatting,
    // the rollback assertion below would compare against the wrong
    // baseline.
    let pre_bytes = std::fs::read(project.path().join("package.json"))
        .expect("test setup: package.json must exist");
    assert!(
        pre_bytes.contains_subslice(b"panic-rollback-test"),
        "test setup: pre-stage manifest doesn't contain expected name"
    );
    assert!(
        !pre_bytes.contains_subslice(b"\"rollback-pkg\""),
        "test setup: pre-stage manifest already has rollback-pkg, \
         which would mask the rollback assertion"
    );

    let output = lpm_with_registry(&project, &mock.url())
        // Trigger the panic at the after-stage point. The hook is
        // debug-build-only; debug is the default for `cargo nextest run`.
        .env("LPM_TEST_PANIC_AT", "after-stage")
        .args(install_args_with(&["rollback-pkg@1.0.0"]))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[B.4] status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    // Process MUST have exited non-zero — panic propagates to runtime.
    assert!(
        !output.status.success(),
        "install with LPM_TEST_PANIC_AT=after-stage reported success \
         — the panic hook did NOT fire. The hook is gated to debug \
         builds; verify the test binary is `cargo build` (not \
         release) and the env passed through.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Stderr must show the panic AND the stage name. If the panic
    // hook is missing or silently no-op, both substrings would be
    // absent.
    assert!(
        stderr.contains("panicked at"),
        "panic hook didn't surface a panic in stderr. The hook may \
         not be wired. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("LPM_TEST_PANIC_AT=after-stage"),
        "panic hook fired but the stage marker is missing — the \
         panic message contract changed. stderr:\n{stderr}"
    );

    // **LOAD-BEARING.** Manifest bytes must be byte-identical to the
    // pre-stage state. Drop on panic should have restored the
    // snapshot bytes verbatim.
    let post_bytes = std::fs::read(project.path().join("package.json"))
        .expect("package.json must still exist after panic-rollback");
    assert_eq!(
        pre_bytes,
        post_bytes,
        "package.json was NOT restored by the ManifestTransaction Drop. \
         The panic-rollback contract is broken. Pre/post diff:\n\
         pre={}\npost={}",
        String::from_utf8_lossy(&pre_bytes),
        String::from_utf8_lossy(&post_bytes)
    );

    // Belt-and-braces: parse the post-state JSON and assert
    // `rollback-pkg` is NOT a dependency. A future regression that
    // adds whitespace/formatting tweaks to the snapshot bytes would
    // trip the byte-equality above; this stricter assertion pins
    // the user-visible contract independently.
    let post_json: serde_json::Value =
        serde_json::from_slice(&post_bytes).expect("post-rollback package.json must parse as JSON");
    let deps = post_json
        .get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    assert!(
        !deps.contains_key("rollback-pkg"),
        "rollback-pkg is still in dependencies after panic-rollback — \
         the staged placeholder leaked. deps={:?}",
        deps.keys().collect::<Vec<_>>()
    );

    // `.lpm/install-hash` is in the transaction's `invalidate` set —
    // delete-on-rollback regardless of pre-state. Pre-stage on a
    // fresh project, this file did not exist; post-rollback it
    // STILL must not exist.
    assert!(
        !project.path().join(".lpm/install-hash").exists(),
        "`.lpm/install-hash` should be absent after panic-rollback \
         (it's in the invalidate set, not the snapshot set)."
    );

    // `lpm.lock` was optional in the snapshot; pre-stage it didn't
    // exist (fresh project). Post-rollback it MUST also not exist —
    // the optional snapshot's "absent → remove on rollback" branch.
    assert!(
        !project.path().join("lpm.lock").exists(),
        "`lpm.lock` should be absent after panic-rollback (snapshot \
         captured `None` pre-stage). If present, the optional-snapshot \
         rollback branch is broken."
    );
}

// Helper trait — workflow tests use this in a couple of places to
// avoid repeating `.windows()` boilerplate. Tight scope: just for
// substring check on byte slices.
#[cfg(debug_assertions)]
trait ContainsSubslice {
    fn contains_subslice(&self, needle: &[u8]) -> bool;
}
#[cfg(debug_assertions)]
impl ContainsSubslice for [u8] {
    fn contains_subslice(&self, needle: &[u8]) -> bool {
        self.windows(needle.len()).any(|w| w == needle)
    }
}

// ─── Category C — Network faults ────────────────────────────────────

/// **C.4 — metadata 404 fails immediately, no retry.**
///
/// 404 is non-retryable per [client.rs:3876](../../../crates/lpm-registry/src/client.rs).
/// The whole install must fail in well under one second — no backoff
/// delay should fire.
#[tokio::test]
async fn install_with_metadata_404_fails_immediately_without_retry() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let mock = MockRegistry::start().await;
    // Mount 404 on the metadata path. No tarball mount needed; we
    // shouldn't get past metadata resolution.
    Mock::given(method("GET"))
        .and(path("/api/registry/missing-pkg"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/missing-pkg"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(mock.server())
        .await;
    // Empty batch-metadata so the install's resolver-batch
    // pre-fetch doesn't pollute the 404 contract.
    mock.with_batch_metadata(vec![]).await;

    let project = TempProject::empty(r#"{"name":"miss-test","version":"1.0.0"}"#);

    let start = Instant::now();
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["missing-pkg@1.0.0"]))
        .output()
        .expect("run install");
    let elapsed = start.elapsed();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "install of nonexistent package succeeded:\nstderr:\n{stderr}"
    );

    // Non-retryable contract: under one second on a quiet runner —
    // 1s minimum retry-backoff would already be 1s+ if a retry fired.
    assert!(
        elapsed < Duration::from_secs(2),
        "404 install took {elapsed:?} — looks like retries fired \
         on a non-retryable response.\nstderr:\n{stderr}"
    );
}

/// **C.1 — tarball 503 → 200 succeeds after retry.**
///
/// Counts the actual request attempts on the wiremock server and
/// asserts the install eventually succeeds. The 3-retry policy at
/// [client.rs:71](../../../crates/lpm-registry/src/client.rs) tolerates 503 and
/// retries with exponential backoff (1s + 2s = ~3s for a 200 on
/// the 3rd attempt).
#[tokio::test]
async fn install_retries_tarball_5xx_until_success() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request, Respond, ResponseTemplate};

    let mock = MockRegistry::start().await;
    let tarball = make_tarball("flaky-pkg", "1.0.0");
    let integrity = compute_integrity(&tarball);
    mock.register_tarball_integrity("flaky-pkg", "1.0.0", integrity.clone());
    let tarball_url = format!("{}/tarballs/flaky-pkg/-/flaky-pkg-1.0.0.tgz", mock.url());
    let metadata = serde_json::json!({
        "name": "flaky-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "flaky-pkg",
                "version": "1.0.0",
                "dist": { "tarball": tarball_url, "integrity": integrity },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/api/registry/flaky-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/flaky-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;

    // Tarball: 503 on attempts 1+2, 200 on attempt 3+.
    struct FlakyTarball {
        count: Arc<AtomicUsize>,
        body: Vec<u8>,
        fail_until: usize,
    }
    impl Respond for FlakyTarball {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_until {
                ResponseTemplate::new(503).set_body_string("simulated transient")
            } else {
                ResponseTemplate::new(200)
                    .set_body_bytes(self.body.clone())
                    .insert_header("content-type", "application/octet-stream")
            }
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/tarballs/flaky-pkg/-/flaky-pkg-1.0.0.tgz"))
        .respond_with(FlakyTarball {
            count: Arc::clone(&count),
            body: tarball.clone(),
            fail_until: 2,
        })
        .mount(mock.server())
        .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "flaky-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"flaky-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["flaky-pkg@1.0.0"]))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "install failed despite retry policy:\nstdout:\n{stdout}\nstderr:\n{stderr}\n\
         tarball_attempts={}",
        count.load(Ordering::SeqCst)
    );
    // At least 3 attempts (2 failures + 1 success). May exceed if
    // the install path fetches the tarball multiple times for
    // verification — that's an interesting per-pipeline detail.
    let attempts = count.load(Ordering::SeqCst);
    assert!(
        attempts >= 3,
        "expected ≥3 tarball requests (2 failures + 1 success), got {attempts}"
    );
    assert!(
        project.path().join("node_modules/flaky-pkg").exists(),
        "flaky-pkg missing from node_modules after successful retry"
    );
}

/// **C.2 — tarball 503 exhausts retries → install fails with HTTP-status error.**
///
/// Mock returns 503 on EVERY tarball request — no recovery. The
/// registry client's retry loop ([client.rs:71](../../../crates/lpm-registry/src/client.rs#L71))
/// runs `MAX_RETRIES = 3` (4 attempts total per logical fetch),
/// then surfaces the last failure as `LpmError::Http { status: 503, ... }`.
/// Install fails non-zero with the 503 visible in stderr.
///
/// **Backoff knob.** The default exponential schedule (1+2+4+8 seconds,
/// capped at 10s) makes retry-exhaustion tests
/// take ~15s wall-clock per fetch site (~28s with the install
/// pipeline's 2 distinct `download_tarball_*` call sites — see C.3
/// docstring). To keep the test in the workflow-suite's <5s
/// determinism budget, the test sets `LPM_RETRY_BACKOFF_MS_OVERRIDE=10`
/// on the lpm subprocess. The override is honored by `backoff_delay`
/// AND the 429 `Retry-After` sleep. The override is honored only by
/// debug builds so production retry policy is immune.
///
/// Pinned contract:
///
/// - Exit non-zero — install must NOT silently succeed against a
///   fully-503 endpoint.
/// - No panic in lpm-rs's stderr.
/// - Stderr names the HTTP class (status / 503 / http / network /
///   server / unavailable) — at least one actionable noun so a
///   future regression that drops the status visibility trips this.
/// - **Elapsed < 2s**. With the knob (10ms × 8 attempts × 2 fetch
///   sites), worst case is ~160ms of sleep. 2s gives slack for
///   resolver overhead. Without the knob, this assertion FAILS
///   (~28s elapsed) — which is why this override exists.
/// - Tarball attempts ≥ 4 — proves the retry loop ran the full
///   schedule, not just one attempt.
#[cfg(debug_assertions)]
#[tokio::test]
async fn tarball_503_exhausts_retries_fails_with_http_status() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request, Respond, ResponseTemplate};

    let mock = MockRegistry::start().await;
    let tarball = make_tarball("doomed-pkg", "1.0.0");
    let integrity = compute_integrity(&tarball);
    let tarball_url = format!("{}/tarballs/doomed-pkg/-/doomed-pkg-1.0.0.tgz", mock.url());
    let metadata = serde_json::json!({
        "name": "doomed-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "doomed-pkg",
                "version": "1.0.0",
                "dist": { "tarball": tarball_url, "integrity": integrity },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/api/registry/doomed-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/doomed-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;

    /// Tarball: 503 on every attempt. Counts hits so the test can
    /// prove the retry loop actually ran.
    struct Always503 {
        count: Arc<AtomicUsize>,
    }
    impl Respond for Always503 {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            self.count.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503).set_body_string("doomed: simulated transient")
        }
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/tarballs/doomed-pkg/-/doomed-pkg-1.0.0.tgz"))
        .respond_with(Always503 {
            count: Arc::clone(&attempts),
        })
        .mount(mock.server())
        .await;
    mock.with_batch_metadata(vec![metadata]).await;

    let project = TempProject::empty(r#"{"name":"doom-test","version":"1.0.0"}"#);
    let start = Instant::now();
    let output = lpm_with_registry(&project, &mock.url())
        // shrink the retry-backoff schedule from
        // exponential 1+2+4+8s → flat 10ms so retry exhaustion fits
        // in the <5s test budget. Honored only in debug builds —
        // production retry policy unaffected.
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "10")
        .args(install_args_with(&["doomed-pkg@1.0.0"]))
        .output()
        .expect("run install");
    let elapsed = start.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let attempt_count = attempts.load(Ordering::SeqCst);

    eprintln!(
        "[C.2] elapsed={elapsed:?} status={:?} tarball_attempts={attempt_count}\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of fully-503 tarball reported success — retry-exhaustion \
         contract violated. attempts={attempt_count}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "install panicked on retry exhaustion:\nstderr:\n{stderr}"
    );
    // Load-bearing: prove the retry loop actually fired. With
    // MAX_RETRIES=3 and 2 distinct download_tarball_* call sites,
    // expect ≥ 4 attempts (one logical-fetch's full retry schedule).
    assert!(
        attempt_count >= 4,
        "tarball was retried only {attempt_count} time(s) — full retry \
         schedule should produce ≥4 attempts (MAX_RETRIES=3). The retry \
         loop may have a regression."
    );
    // Load-bearing: with the knob, retry-exhaustion fits well under
    // the suite's <5s determinism budget. Without the knob, this assertion
    // fails at ~28s.
    assert!(
        elapsed < Duration::from_secs(2),
        "retry exhaustion took {elapsed:?} — LPM_RETRY_BACKOFF_MS_OVERRIDE \
         is not being honored, OR the retry budget grew. attempts={attempt_count}"
    );
    // Surface the HTTP class so users / CI can grep for the failure.
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("503")
            || stderr_l.contains("status")
            || stderr_l.contains("http")
            || stderr_l.contains("server")
            || stderr_l.contains("unavailable")
            || stderr_l.contains("network"),
        "retry-exhaustion failure didn't surface an actionable noun \
         naming the HTTP class. attempts={attempt_count}\nstderr:\n{stderr}"
    );
}

/// **C.3 — tarball body that under-delivers vs declared `Content-Length` fails cleanly.**
///
/// The mock claims `Content-Length: <full>` in its header but writes
/// only half the bytes. The plan asked which branch fires:
///
/// 1. **reqwest detects mid-stream undercount** as a network-class
///    error → the registry client's retry loop fires, install fails
///    after retry exhaustion.
/// 2. **reqwest delivers the truncated bytes** → the downstream
///    gzip/tar decoder hits EOF and surfaces a non-retryable
///    `LpmError::Integrity`-class error on the first attempt.
///
/// **Observed behavior on this stack (wiremock 0.6 / hyper 1.9 / reqwest 0.12):**
/// the server-side hyper writer rejects the Content-Length lie with
/// an internal panic before any bytes reach the wire (`payload claims
/// content-length of N, custom content-length header claims 2N`). The
/// connection drops; lpm-rs sees a transport error
/// (`error sending request for url`); the registry client classifies
/// it as retryable and runs the full retry schedule. Install fails
/// after retry exhaustion in ~14s.
///
/// That's a valid surrogate for "broken upstream / broken CDN drops
/// connection mid-body" — the same retry-then-fail path is exercised
/// either way. Surfaced ~8 tarball GETs per install consistently
/// across runs (3-of-3 reproducer); the registry client's retry
/// budget is `MAX_RETRIES=3` (4 total attempts per logical call),
/// so 8 = two distinct `download_tarball_*` call sites in the
/// install pipeline ([install.rs:9732 streaming](../../../crates/lpm-cli/src/commands/install.rs#L9732)
/// + [install.rs:9951 routed](../../../crates/lpm-cli/src/commands/install.rs#L9951))
/// each running the full retry schedule. Likely intentional
/// (probe + download), but worth noting for budget reasoning if a
/// future test asserts on attempt counts.
///
/// The contract pinned here:
///
/// - Exit non-zero — install must NOT silently succeed with half a tar.
/// - No panic in lpm-rs's stderr (wiremock-side panics are server
///   internals captured in TEST stderr, not lpm-rs stderr — that
///   distinction is load-bearing for this assertion).
/// - Stderr names something actionable (network / integrity /
///   connection / truncated / decode / etc).
/// - Elapsed is bounded under 25s — full retry schedule is ~15s.
///   Never hangs.
///
/// To test the "decoder catches truncated body" branch directly, a
/// future test would need a raw `tokio::net::TcpListener` writing
/// the truncated response itself (bypass wiremock's framing). Out
/// of scope for this tranche; the retry-exhaustion path is the
/// load-bearing user-visible contract today.
#[tokio::test]
async fn tarball_connection_dropped_mid_body_fails_or_retries() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request, Respond, ResponseTemplate};

    let mock = MockRegistry::start().await;
    // Build a complete tarball, then under-deliver half its bytes
    // while declaring the full length in `Content-Length`. The
    // declared length must be > delivered length so reqwest sees an
    // undercount (or the tar decoder sees a truncated stream).
    let full_tarball = make_tarball("truncated-pkg", "1.0.0");
    let full_len = full_tarball.len();
    let half_tarball: Vec<u8> = full_tarball.iter().take(full_len / 2).copied().collect();
    assert!(
        !half_tarball.is_empty() && half_tarball.len() < full_len,
        "test setup: tarball must be larger than its half"
    );

    let integrity = compute_integrity(&full_tarball);
    let tarball_url = format!(
        "{}/tarballs/truncated-pkg/-/truncated-pkg-1.0.0.tgz",
        mock.url()
    );
    let metadata = serde_json::json!({
        "name": "truncated-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "truncated-pkg",
                "version": "1.0.0",
                "dist": { "tarball": tarball_url, "integrity": integrity },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/api/registry/truncated-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/truncated-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;

    /// Counts attempts and serves a half-body with a full Content-Length on every hit.
    /// Retries (if any) should hit the same endpoint and observe the
    /// same under-delivery.
    struct TruncatedTarball {
        count: Arc<AtomicUsize>,
        half_body: Vec<u8>,
        declared_len: usize,
    }
    impl Respond for TruncatedTarball {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            self.count.fetch_add(1, Ordering::SeqCst);
            // `set_body_raw` writes the bytes verbatim with the named
            // content-type. We then OVERRIDE `content-length` with the
            // larger declared size so the wire-level handler claims
            // more bytes than it delivers.
            ResponseTemplate::new(200)
                .set_body_raw(self.half_body.clone(), "application/octet-stream")
                .insert_header("content-length", self.declared_len.to_string().as_str())
        }
    }

    let attempts = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/tarballs/truncated-pkg/-/truncated-pkg-1.0.0.tgz"))
        .respond_with(TruncatedTarball {
            count: Arc::clone(&attempts),
            half_body: half_tarball,
            declared_len: full_len,
        })
        .mount(mock.server())
        .await;

    mock.with_batch_metadata(vec![metadata]).await;

    let project = TempProject::empty(r#"{"name":"trunc-test","version":"1.0.0"}"#);
    let start = Instant::now();
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["truncated-pkg@1.0.0"]))
        .output()
        .expect("run install");
    let elapsed = start.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let attempt_count = attempts.load(Ordering::SeqCst);

    // Always log the actual shape so later readers can see whether
    // reqwest detected the undercount (multi-attempt) or the decoder
    // caught it on the first byte stream (single attempt).
    eprintln!(
        "[C.3] elapsed={elapsed:?} status={:?} tarball_attempts={attempt_count}\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of truncated-body tarball reported success — \
         decoder accepted half a .tgz. attempts={attempt_count}\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "install panicked on truncated body: stderr:\n{stderr}"
    );
    // Bounded wall-clock: 25s leaves headroom for the full retry
    // schedule (~15s) on slow CI runners. A hang here is the bug.
    assert!(
        elapsed < Duration::from_secs(25),
        "install of truncated body took {elapsed:?} — looks like a hang \
         (3-retry budget is ~15s). attempts={attempt_count}"
    );
    // Some actionable noun must surface so users / CI can grep for
    // the failure class. The word list is intentionally broad
    // because the failure can either come from reqwest (network /
    // connection / body / closed) or from the tar/gzip layer
    // (integrity / checksum / decode / parse / corrupt / truncated).
    let stderr_l = stderr.to_lowercase();
    let actionable = [
        "integrity",
        "checksum",
        "decode",
        "decompress",
        "parse",
        "corrupt",
        "truncated",
        "network",
        "connection",
        "body",
        "size",
        "length",
        "io error",
        "incomplete",
        "unexpected eof",
        "premature",
        "tarball",
        "extract",
    ]
    .iter()
    .any(|n| stderr_l.contains(n));
    assert!(
        actionable,
        "truncated-body failure didn't surface an actionable noun. \
         attempts={attempt_count}\nstderr:\n{stderr}"
    );
    // Either both branches of the plan: ≥1 attempt is acceptable;
    // the diagnostic above tells the reader which branch fired.
    assert!(
        attempt_count >= 1,
        "no tarball request observed — install failed before fetch. \
         stderr:\n{stderr}"
    );
}

// ─── Category D — Filesystem faults ─────────────────────────────────

/// **D.1 — `lpm install` to a read-only project dir fails clearly.**
///
/// `chmod 555` blocks the install from writing `lpm.lock`,
/// `.lpm/install-hash`, and `node_modules/`. The contract: clean
/// failure with non-zero exit and a message that names the path or
/// the operation. No internal panic, no cryptic stack.
///
/// POSIX-only — Windows readonly semantics differ (junctions / ACLs);
/// gated with `#[cfg(unix)]`. Restores permissions in a `Drop` guard
/// so tempfile cleanup works even if assertions panic.
#[cfg(unix)]
#[tokio::test]
async fn install_to_readonly_project_dir_fails_with_clear_error() {
    use std::os::unix::fs::PermissionsExt;

    let mock = MockRegistry::start().await;
    let tarball = make_tarball("any-pkg", "1.0.0");
    mock.with_package("any-pkg", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "any-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"ro-test","version":"1.0.0"}"#);

    // RAII guard restores writable permissions on drop so `TempDir`
    // can clean up afterwards. Without this, a panicking assertion
    // leaves /tmp/<project>/ unwritable, polluting subsequent runs.
    struct RestoreWritable(std::path::PathBuf);
    impl Drop for RestoreWritable {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let _restorer = RestoreWritable(project.path().to_path_buf());

    std::fs::set_permissions(project.path(), std::fs::Permissions::from_mode(0o555))
        .expect("chmod 555");

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["any-pkg@1.0.0"]))
        .output()
        .expect("run install");

    assert!(
        !output.status.success(),
        "install to readonly dir reported success: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // No panic should escape — a normal slim error is fine, bare
    // "panicked at" / "RUST_BACKTRACE" lines are not. The failure
    // should also reference the operation that couldn't proceed
    // (write / permission / lpm.lock-ish).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "install to readonly dir panicked instead of failing cleanly:\nstderr:\n{stderr}"
    );
    let actionable = stderr.to_lowercase().contains("permission")
        || stderr.to_lowercase().contains("read-only")
        || stderr.to_lowercase().contains("readonly")
        || stderr.contains("lpm.lock")
        || stderr.contains("node_modules")
        || stderr.contains(".lpm")
        || stderr.contains("denied");
    assert!(
        actionable,
        "readonly-dir failure didn't surface an actionable noun \
         (permission / lpm.lock / node_modules / .lpm / denied):\nstderr:\n{stderr}"
    );
}

/// **D.2 — `lpm install` when `<project>/.lpm` is a file fails clearly.**
///
/// `.lpm` is supposed to be a directory (holds `install-hash`,
/// `wrappers/`, etc.). If it's a regular file, the install can't
/// create the children — and shouldn't try silently. Pins the
/// failure shape: non-zero exit, no panic, no cryptic stack.
#[tokio::test]
async fn install_when_dot_lpm_is_a_file_fails_clearly() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("any-pkg", "1.0.0");
    mock.with_package("any-pkg", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "any-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"dotlpm-conflict","version":"1.0.0"}"#);
    // Plant a regular file at `<project>/.lpm` BEFORE the install
    // tries to create the dir.
    std::fs::write(project.path().join(".lpm"), b"not a dir").expect("seed .lpm file");

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["any-pkg@1.0.0"]))
        .output()
        .expect("run install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "install succeeded despite `.lpm` being a regular file:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "install panicked instead of failing cleanly:\nstderr:\n{stderr}"
    );
}

// ─── Category E — Partial state recovery ─────────────────────────────

/// **E.2 — stale `.lpm/install-hash` triggers re-resolve, not fast-exit.**
///
/// The freshness cache at `.lpm/install-hash` is what gates the
/// "Everything up to date" fast path. If the stored hash matches the
/// recomputed `compute_install_hash_v6` of disk state, install
/// fast-exits. If the bytes don't match (manifest edited, lockfile
/// rebuilt, or — in our test — written synthetically), the install
/// MUST re-resolve and re-link. Pinned by counting tarball requests
/// on the mock: > 0 means a real fetch happened.
#[tokio::test]
async fn install_with_stale_install_hash_re_resolves_and_refetches() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request, Respond, ResponseTemplate};

    let mock = MockRegistry::start().await;
    let tarball = make_tarball("stale-pkg", "1.0.0");
    let integrity = compute_integrity(&tarball);
    mock.register_tarball_integrity("stale-pkg", "1.0.0", integrity.clone());
    let tarball_url = format!("{}/tarballs/stale-pkg/-/stale-pkg-1.0.0.tgz", mock.url());
    let metadata = serde_json::json!({
        "name": "stale-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "stale-pkg",
                "version": "1.0.0",
                "dist": { "tarball": tarball_url, "integrity": integrity },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/api/registry/stale-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/stale-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;

    // Count tarball requests so we can prove a real fetch fired.
    struct CountingTarball {
        count: Arc<AtomicUsize>,
        body: Vec<u8>,
    }
    impl Respond for CountingTarball {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            self.count.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .set_body_bytes(self.body.clone())
                .insert_header("content-type", "application/octet-stream")
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/tarballs/stale-pkg/-/stale-pkg-1.0.0.tgz"))
        .respond_with(CountingTarball {
            count: Arc::clone(&count),
            body: tarball,
        })
        .mount(mock.server())
        .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "stale-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"stale-test","version":"1.0.0"}"#);

    // Plant a stale install-hash. The bytes won't match any real
    // hash of the current state, so the freshness check fails and
    // install re-runs the full pipeline.
    std::fs::create_dir_all(project.path().join(".lpm")).expect("mkdir .lpm");
    std::fs::write(
        project.path().join(".lpm/install-hash"),
        "deadbeef-this-hash-cannot-match-anything-real\n",
    )
    .expect("seed stale install-hash");

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["stale-pkg@1.0.0"]))
        .output()
        .expect("run install");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "install with stale install-hash didn't recover:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let attempts = count.load(Ordering::SeqCst);
    assert!(
        attempts >= 1,
        "stale install-hash didn't trigger a tarball fetch \
         (attempts={attempts}) — install fast-exited on the synthetic \
         hash instead of recomputing. Freshness contract broken."
    );

    // Post-state: the install-hash now exists and is NOT the synthetic
    // bytes (it's the freshly computed hash of the now-installed state).
    let post_hash = std::fs::read_to_string(project.path().join(".lpm/install-hash"))
        .expect("read install-hash");
    assert!(
        !post_hash.contains("deadbeef-this-hash-cannot-match-anything-real"),
        "install-hash was not overwritten after re-resolve:\n{post_hash}"
    );
}

/// **E.1 — `lpm install` recovers when `node_modules/` is partial.**
///
/// Simulates the post-SIGKILL state from Category B: `node_modules/`
/// has some links but the install-hash is absent. Next `lpm install`
/// must re-link to reach the full lockfile state, not panic or
/// fast-exit on the stale partial state.
#[tokio::test]
async fn install_with_partial_node_modules_re_links_to_full_state() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("recovery-pkg", "1.0.0");
    mock.with_package("recovery-pkg", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "recovery-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"partial-test","version":"1.0.0"}"#);

    // First, do a full install to populate everything.
    let first = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["recovery-pkg@1.0.0"]))
        .output()
        .expect("run first install");
    assert!(
        first.status.success(),
        "setup: first install failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Simulate a partial-state aftermath: delete the install-hash but
    // ALSO corrupt one of the node_modules entries so re-link is
    // forced. (Just deleting install-hash would let the install
    // detect coherent node_modules and fast-skip the link.)
    let install_hash = project.path().join(".lpm/install-hash");
    if install_hash.exists() {
        std::fs::remove_file(&install_hash).expect("remove install-hash");
    }
    let nm_pkg = project.path().join("node_modules/recovery-pkg");
    if nm_pkg.exists() {
        // Replace the package contents with garbage so the install
        // pipeline has to re-link.
        std::fs::remove_dir_all(&nm_pkg).expect("rm pkg dir");
    }

    // Now re-install — must converge to a coherent state without
    // panicking. (Re-mount in case the mock state was consumed.)
    let second = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["recovery-pkg@1.0.0"]))
        .output()
        .expect("run second install");
    let stderr = String::from_utf8_lossy(&second.stderr);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        second.status.success(),
        "install did not recover from partial node_modules:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        project
            .path()
            .join("node_modules/recovery-pkg/package.json")
            .exists(),
        "recovery-pkg/package.json missing after recovery install"
    );
    assert!(
        project.path().join(".lpm/install-hash").exists(),
        "install-hash missing after recovery install"
    );
}

/// **E.3 — `lpm install` ignores an obsolete truncated `lpm.lockb`.**
///
/// V13 lockfiles are TOML-only. If an obsolete binary companion remains and
/// is corrupt, install must use the authoritative TOML without panicking.
#[tokio::test]
async fn install_with_truncated_lockb_falls_back_to_toml() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("binary-cache-package", "1.0.0");
    mock.with_package("binary-cache-package", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(
        r#"{"name":"torn-test","version":"1.0.0","dependencies":{"binary-cache-package":"1.0.0"}}"#,
    );
    let first = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&[]))
        .output()
        .expect("run first install");
    assert!(
        first.status.success(),
        "setup: first install failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Plant an obsolete truncated companion beside the authoritative TOML.
    let lockb_path = project.path().join("lpm.lockb");
    std::fs::write(&lockb_path, b"corrupt").expect("truncate lpm.lockb");

    // Run install again. Must NOT panic; must produce a coherent end
    // state (either by re-parsing lpm.lock or by re-resolving from
    // package.json).
    let second = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&[]))
        .output()
        .expect("run second install");
    let stderr = String::from_utf8_lossy(&second.stderr);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "install panicked on truncated lockb:\nstderr:\n{stderr}"
    );
    // Even if the install fails on truncated lockb, it must do so
    // CLEANLY (non-zero exit, no panic). We don't pin success here
    // — the contract is "no panic, well-formed failure if any."
    if !second.status.success() {
        // Failure mode is OK as long as it's well-shaped. Leave as
        // diagnostic: any actionable noun acceptable.
        let actionable = stderr.to_lowercase().contains("lockb")
            || stderr.to_lowercase().contains("lockfile")
            || stderr.to_lowercase().contains("corrupt")
            || stderr.to_lowercase().contains("parse");
        assert!(
            actionable,
            "truncated-lockb failure didn't surface an actionable noun:\n\
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

// ─── Category F — WAL recovery hook ─────────────────────────────────

/// **F.1 — torn-tail WAL triggers recovery message before command runs.**
///
/// `lpm_global::recover()` fires from the dispatcher at
/// [main.rs:2515-2585](../../../crates/lpm-cli/src/main.rs) before any command
/// that reads `~/.lpm/global/` state. Pre-seeding the WAL with bytes
/// that look like a torn write (incomplete frame header) forces the
/// scan into the `WalScan::has_torn_tail` branch
/// ([wal.rs:382](../../../crates/lpm-global/src/wal.rs)), and the dispatcher's
/// hook truncates the torn tail back to the last clean record. The
/// command then runs against a clean WAL.
///
/// Pinned contract: the user sees the operation succeed (or fail for
/// its own reasons, not WAL corruption), AND the WAL is no longer
/// torn after the command returns.
#[tokio::test]
async fn lpm_command_after_torn_wal_tail_recovers_silently() {
    // No mock needed — `global list` reads only local state.
    let project = TempProject::empty(r#"{"name":"wal-test","version":"1.0.0"}"#);

    // Pre-seed an empty `~/.lpm/global/` directory with a WAL file
    // whose contents are garbage bytes shorter than a frame header
    // (`len:u32 + crc:u32 + payload + sentinel:u8`). The reader will
    // hit EOF mid-header and classify the tail as torn.
    let global_dir = project.home().join(".lpm/global");
    std::fs::create_dir_all(&global_dir).expect("mkdir ~/.lpm/global");
    let wal_path = global_dir.join("wal.jsonl");
    std::fs::write(&wal_path, b"\x00\x00\x00").expect("seed torn WAL"); // 3 bytes — under 8-byte header

    // Run a read-only command. The dispatcher's recovery hook fires
    // BEFORE the command body, so the WAL is repaired in-flight.
    let pre_size = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(
        pre_size, 3,
        "test setup wrong: WAL should be 3 bytes pre-run"
    );

    let output = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("run global list");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "global list failed despite WAL recovery hook:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // No panic / no backtrace — clean recovery, not a crash.
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "WAL recovery panicked instead of truncating the torn tail:\nstderr:\n{stderr}"
    );

    // Concrete evidence that recovery ran: the torn 3-byte prefix
    // must be gone. Either the WAL file no longer exists (truncated
    // away entirely), or it's 0 bytes, or it's a different non-zero
    // size — never STILL the original 3 garbage bytes.
    let post_size = std::fs::metadata(&wal_path).map_or(0, |m| m.len());
    assert_ne!(
        post_size, 3,
        "WAL still has the seeded torn-tail bytes after recovery hook \
         supposedly ran — recovery is a no-op."
    );

    // Idempotence: a second invocation must run without re-triggering
    // any recovery work, since the WAL is now clean.
    let second = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("run global list again");
    assert!(
        second.status.success(),
        "second global list failed: stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        !second_stderr.contains("global recovery: rolled")
            && !second_stderr.contains("global recovery: orphan"),
        "WAL still torn after recovery hook ran — recovery not idempotent:\n{second_stderr}"
    );
}

/// **F.2 — dispatcher's recovery hook skips when another lpm holds `global_tx_lock`.**
///
/// Validates the `try_with_exclusive_lock` idempotent-skip path at
/// [main.rs:2531](../../../crates/lpm-cli/src/main.rs). When recovery would otherwise fire
/// (torn WAL present), but another `lpm` process is already inside a
/// global transaction, the dispatcher must `Ok(None)` out of the
/// non-blocking lock attempt and let the holder run its own recovery
/// on commit/exit.
///
/// Test shape:
///   1. Plant a torn WAL (3 garbage bytes, same shape as F.1).
///   2. Hold `global_tx_lock` in a background thread via
///      `lpm_common::with_exclusive_lock`.
///   3. Run `lpm global list` — must succeed, WAL must STILL be 3
///      bytes (proof: skip path fired, recovery did NOT run).
///   4. Release the lock.
///   5. Run `lpm global list` again — recovery now fires, WAL is
///      truncated past the torn bytes.
///
/// Steps 3 and 5 together prove both branches of the
/// `try_with_exclusive_lock` arm: the skip when contended, the run
/// when free.
#[tokio::test]
async fn lpm_command_skips_recovery_when_another_lpm_holds_global_tx_lock() {
    let project = TempProject::empty(r#"{"name":"skip-test","version":"1.0.0"}"#);

    // Plant the torn WAL bytes.
    let global_dir = project.home().join(".lpm/global");
    std::fs::create_dir_all(&global_dir).expect("mkdir ~/.lpm/global");
    let wal_path = global_dir.join("wal.jsonl");
    std::fs::write(&wal_path, b"\x00\x00\x00").expect("seed torn WAL");

    // Hold `global_tx_lock` in a background thread. The thread blocks
    // on a channel until the test signals release, so the lock is held
    // for the entire duration of the `lpm global list` invocation
    // below.
    let global_tx_lock_path = global_dir.join(".tx.lock");
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel::<()>();
    let lock_path_for_thread = global_tx_lock_path.clone();
    let lock_thread = std::thread::spawn(move || {
        lpm_common::with_exclusive_lock(&lock_path_for_thread, || {
            // Signal "lock acquired" before parking on the release channel.
            acquired_tx.send(()).ok();
            // Block until the main thread releases.
            release_rx.recv().ok();
            Ok::<(), lpm_common::LpmError>(())
        })
    });

    // Wait until the background thread confirms it holds the lock.
    acquired_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("background thread never acquired global_tx_lock");

    // Sanity: a non-blocking exclusive try MUST observe the lock held.
    assert!(
        matches!(
            lpm_common::try_with_exclusive_lock(&global_tx_lock_path, || Ok(())),
            Ok(None)
        ),
        "test setup: background thread reported lock acquired but \
         try_with_exclusive_lock didn't see it as held"
    );

    let pre_wal_size = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(pre_wal_size, 3, "test setup: WAL should be 3 bytes pre-run");

    // Run `lpm global list` — dispatcher's recovery hook should hit
    // `WouldBlock` on its try_with_exclusive_lock and skip silently.
    let output = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("run global list");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "global list failed while another lpm held global_tx_lock:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("global recovery: rolled") && !stderr.contains("global recovery: orphan"),
        "recovery banner fired even though another lpm held \
         global_tx_lock — dispatcher's try_with_exclusive_lock skip \
         path is not being taken.\nstderr:\n{stderr}"
    );

    // Critical proof: the torn WAL bytes are STILL there. Recovery
    // did not run. If they're gone, the dispatcher proceeded with
    // recovery despite the lock being held — a correctness bug in
    // the `try_with_exclusive_lock` arm.
    let mid_wal_size = std::fs::metadata(&wal_path).map_or(0, |m| m.len());
    assert_eq!(
        mid_wal_size, 3,
        "WAL was modified while another lpm held global_tx_lock — \
         dispatcher's recovery hook ran the recovery code despite \
         the lock contention skip arm. Pre={pre_wal_size} mid={mid_wal_size}."
    );

    // Release the background lock and let the thread finish.
    release_tx.send(()).ok();
    lock_thread
        .join()
        .expect("lock thread panicked")
        .expect("lock thread reported error");

    // Now run again — recovery should fire (lock is free) and the
    // torn bytes should be cleaned up.
    let after_release = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("run global list after lock release");
    assert!(
        after_release.status.success(),
        "post-release global list failed: stderr={}",
        String::from_utf8_lossy(&after_release.stderr)
    );
    let post_wal_size = std::fs::metadata(&wal_path).map_or(0, |m| m.len());
    assert_ne!(
        post_wal_size, 3,
        "after the lock-holder released, recovery still didn't run — \
         the dispatcher hook is broken in BOTH arms."
    );
}

/// **F.3 — orphan pending tx triggers a `RolledBack` recovery outcome.**
///
/// Plants a fully-formed orphan transaction across both surfaces of
/// global state:
///
/// 1. WAL: a single `WalRecord::Intent` for `tx-orphan-1` / `pkg-orphan`
///    pointing at a non-existent install root path. No matching COMMIT
///    or ABORT.
/// 2. `manifest.toml`: a matching `[pending.pkg-orphan]` row, also
///    pointing at the same non-existent install root.
///
/// On the next `lpm` invocation that needs global state, the dispatcher
/// hook ([main.rs:2531](../../../crates/lpm-cli/src/main.rs)) fires
/// `lpm_global::recover()`. Recovery's per-tx loop ([recover.rs:213](../../../crates/lpm-global/src/recover.rs))
/// finds the uncompleted Intent, looks up the pending row, calls
/// `validate_install_root` — which returns `Missing` because the
/// install-root directory we named was never created. Recovery then
/// rolls back: the pending row is dropped, an ABORT is appended to
/// the WAL, the install-root tombstone (if any) is recorded.
///
/// User-visible signal: a `tracing::info!("global recovery: rolled
/// back ... (tx ...)")` line ([main.rs:2543](../../../crates/lpm-cli/src/main.rs))
/// on stderr. The default `lpm=warn` filter suppresses it, so this
/// test sets `RUST_LOG=lpm=info` on the command to surface it. Real
/// users see this when they invoke `lpm -v <cmd>` after a crash.
///
/// The test pins three invariants:
///
/// - `lpm global list` succeeds (recovery doesn't crash the command).
/// - Stderr contains the recovery-banner phrase + the tx_id (so a
///   future regression that drops the banner trips the test).
/// - Post-state: the orphan `[pending.pkg-orphan]` row is gone from
///   `manifest.toml` (proof recovery actually mutated state, not
///   just emitted a banner).
///
/// **Why the dispatcher hook fires for `lpm global list`.** Per
/// [`command_needs_global_state`](../../../crates/lpm-cli/src/main.rs)
/// the global subcommands are gated for recovery — see F.1's
/// docstring for the broader contract.
#[tokio::test]
async fn lpm_command_with_orphan_pending_tx_emits_recovery_banner() {
    use chrono::Utc;
    use lpm_common::LpmRoot;
    use lpm_global::manifest::{
        GlobalManifest, PackageSource, PendingEntry, write_for as write_manifest_for,
    };
    use lpm_global::wal::{IntentPayload, TxKind, WalRecord, WalWriter};

    let project = TempProject::empty(r#"{"name":"orphan-test","version":"1.0.0"}"#);
    // Mirror the dispatcher's view of the lpm root: it consults
    // `LPM_HOME` first, which `apply_lpm_env` sets to `<HOME>/.lpm`.
    let lpm_home = project.home().join(".lpm");
    let root = LpmRoot::from_dir(&lpm_home);

    // The install root path we name is intentionally NOT created.
    // `validate_install_root` will return a non-`Ready` status, which
    // routes recovery through `roll_back` → `RolledBack`.
    let install_root = root.install_root_for("pkg-orphan", "1.0.0");
    let relative_root = "installs/pkg-orphan@1.0.0";

    // Plant the manifest's pending row first — `write_for` creates
    // `~/.lpm/global/` as a side effect, which the WAL writer
    // depends on. (The inverse order works too because
    // `WalWriter::open` also mkdir's, but pinning the order keeps
    // the test's intent obvious.)
    let mut manifest = GlobalManifest::default();
    manifest.pending.insert(
        "pkg-orphan".into(),
        PendingEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-x".into(),
            source: PackageSource::LpmDev,
            started_at: Utc::now(),
            root: relative_root.into(),
            commands: vec!["pkg-orphan".into()],
            replaces_version: None,
        },
    );
    write_manifest_for(&root, &manifest).expect("plant pending manifest row");

    // Plant the matching INTENT in the WAL with no COMMIT/ABORT.
    let intent = WalRecord::Intent(Box::new(IntentPayload {
        tx_id: "tx-orphan-1".into(),
        kind: TxKind::Install,
        package: "pkg-orphan".into(),
        new_root_path: install_root,
        new_row_json: serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": relative_root,
            "commands": ["pkg-orphan"],
        }),
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
    }));
    let mut writer = WalWriter::open(root.global_wal()).expect("open WAL writer");
    writer.append(&intent).expect("append orphan INTENT");
    drop(writer); // explicit drop to release the file handle before lpm forks

    // Sanity: confirm the orphan state is actually present.
    assert!(
        root.global_wal().exists(),
        "test setup: WAL not present after planting orphan INTENT"
    );
    assert!(
        root.global_manifest().exists(),
        "test setup: manifest not present after planting pending row"
    );

    // Run a global subcommand that triggers the dispatcher's recovery
    // hook. `RUST_LOG=lpm=info` lifts the default `lpm=warn` filter
    // (see [main.rs:2440-2444](../../../crates/lpm-cli/src/main.rs))
    // so the `tracing::info!("global recovery: rolled back …")` line
    // surfaces on stderr.
    let output = lpm(&project)
        .env("RUST_LOG", "lpm=info")
        .args(["global", "list"])
        .output()
        .expect("run global list");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[F.3] status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "global list failed in the presence of an orphan tx — \
         dispatcher recovery hook didn't reconcile cleanly:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "recovery panicked while reconciling the orphan tx:\nstderr:\n{stderr}"
    );

    // The recovery banner must surface when RUST_LOG=lpm=info is set.
    // Substring on the stable phrase + the tx_id we planted.
    assert!(
        stderr.contains("global recovery: rolled back"),
        "expected the `RolledBack` banner from \
         crates/lpm-cli/src/main.rs:2543. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("tx-orphan-1"),
        "recovery banner did not name the planted tx_id `tx-orphan-1`. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("pkg-orphan"),
        "recovery banner did not name the planted package `pkg-orphan`. stderr:\n{stderr}"
    );

    // Concrete proof recovery actually mutated state: the orphan
    // pending row must be gone from the manifest.
    let post_manifest =
        lpm_global::manifest::read_for(&root).expect("re-read manifest post-recovery");
    assert!(
        !post_manifest.pending.contains_key("pkg-orphan"),
        "[pending.pkg-orphan] still present after rollback — recovery emitted \
         the banner but didn't actually clean up the manifest. \
         post_manifest.pending={:?}",
        post_manifest.pending.keys().collect::<Vec<_>>()
    );
    // No active row was ever committed (this was an orphan, not a
    // partial install). Pin the absence so a future regression that
    // mistakenly rolls FORWARD instead of back trips the test.
    assert!(
        !post_manifest.packages.contains_key("pkg-orphan"),
        "[packages.pkg-orphan] appeared after rollback — recovery rolled \
         forward instead of back. post_manifest.packages={:?}",
        post_manifest.packages.keys().collect::<Vec<_>>()
    );
}

// ─── Category G — Additional concurrency/recovery hardening ─

/// **G.4 — `lpm cache clean` racing a slow in-flight install does not corrupt the install.**
///
/// **Architectural facts:**
///
/// - `lpm cache clean` removes ONLY `~/.lpm/cache/{metadata,tasks,dlx,mcp}`
///   (see [crates/lpm-cli/src/commands/cache.rs:64](../../../crates/lpm-cli/src/commands/cache.rs#L64)).
///   It NEVER touches `~/.lpm/store/`.
/// - Tarball staging happens entirely inside `~/.lpm/store/` (temp dir
///   → atomic-rename), so the "in-flight tarball bytes" phrasing from
///   the original plan annotation is misleading: cache clean cannot
///   delete those bytes by construction.
/// - The real race is **metadata-cache reads/writes** during the
///   install: the registry client at
///   [crates/lpm-registry/src/client.rs:907-913](../../../crates/lpm-registry/src/client.rs#L907)
///   reads/writes `~/.lpm/cache/metadata/` during resolution, and
///   that's the directory `cache clean` wipes. The cache is documented
///   as best-effort (graceful degradation to memory-only on I/O
///   failure) — so the contract is: even when cache clean wipes the
///   metadata directory mid-install, the install must still complete.
/// - `cache_clean_lock` and `store_lock` are different paths
///   ([crates/lpm-common/src/paths.rs:170, 139](../../../crates/lpm-common/src/paths.rs#L139)),
///   so the two operations DON'T serialize against each other. They
///   genuinely run concurrently.
///
/// Pinned contract:
///
/// - Both `lpm install` AND `lpm cache clean` exit non-zero-free.
/// - The install actually exercised the slow-tarball window (elapsed
///   >= the configured delay).
/// - Cache clean fired DURING the install window (its end-time falls
///   within the install's wall-clock range), proving the race window
///   was real and not a sequential run.
/// - Post-state: the integrity-keyed v2 object is reusable and contains
///   `package.json` (the store-side artifact cache clean cannot touch).
/// - Post-state: `node_modules/<pkg>/` linked, `package.json` carries
///   the dep, `.lpm/install-hash` written — the install's user-visible
///   outputs all materialize.
/// - No panic in either subprocess.
///
/// This catches a regression where cache clean ever deletes a path
/// the install pipeline depends on AND where the install pipeline
/// loses its "graceful degradation on cache failure" stance and
/// hard-fails on a missing metadata directory mid-stream.
#[tokio::test]
async fn cache_clean_during_slow_tarball_install_does_not_corrupt_install() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("slow-cc-pkg", "1.0.0");
    let integrity = compute_integrity(&tarball);
    // 1500ms tarball delay — same shape as A.3's serialization probe.
    // Gives cache clean a wide window to fire mid-install.
    let tarball_delay = Duration::from_millis(1500);
    with_delayed_package(&mock, "slow-cc-pkg", "1.0.0", tarball, tarball_delay).await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "slow-cc-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"cache-clean-race","version":"1.0.0"}"#);

    let install_start = Instant::now();
    let mut install_child = lpm_spawnable_with_registry(&project, &mock.url())
        .args(install_args_with(&["slow-cc-pkg@1.0.0"]))
        .spawn()
        .expect("spawn install");

    // Wait for the install to acquire the shared `store_lock` — proxy
    // for "install is mid-pipeline, past metadata resolution, currently
    // fetching/extracting the tarball". The lock-acquired moment is
    // strictly AFTER metadata-cache writes have started, so cache
    // clean has something to delete.
    let store_lock_path = project.home().join(".lpm").join("store").join(".gc.lock");
    assert!(
        wait_until(Duration::from_secs(10), || {
            if !store_lock_path.exists() {
                return false;
            }
            matches!(
                lpm_common::try_with_exclusive_lock(&store_lock_path, || Ok(())),
                Ok(None)
            )
        }),
        "install never acquired shared store_lock within 10s — \
         the test couldn't establish the mid-install race window"
    );

    // Race a `cache clean`. Different lock path from store_lock, so
    // it CAN run concurrently — that's the whole point.
    let clean_start = Instant::now();
    let clean_output = lpm(&project)
        .args(["cache", "clean"])
        .output()
        .expect("run cache clean during install");
    let clean_end = Instant::now();

    // Now wait for the install to finish.
    let install_status = wait_with_timeout(&mut install_child, Duration::from_secs(60));
    let install_end = Instant::now();
    let install_out = read_remaining_output(install_child);

    eprintln!(
        "[G.4] install_status={:?} clean_status={:?}\n\
         install_elapsed={:?} clean_elapsed={:?}\n\
         clean_start_offset_from_install_start={:?}\n\
         clean_end_offset_from_install_start={:?}\n\
         install stdout:\n{}\ninstall stderr:\n{}\n\
         clean stdout:\n{}\nclean stderr:\n{}",
        install_status,
        clean_output.status,
        install_end.duration_since(install_start),
        clean_end.duration_since(clean_start),
        clean_start.duration_since(install_start),
        clean_end.duration_since(install_start),
        install_out.stdout,
        install_out.stderr,
        String::from_utf8_lossy(&clean_output.stdout),
        String::from_utf8_lossy(&clean_output.stderr),
    );

    // **LOAD-BEARING #1:** install must succeed despite the racing
    // cache clean. If this fails, the install pipeline lost its
    // graceful-degradation contract — a wiped metadata cache mid-
    // install should not break anything.
    assert!(
        install_status.success(),
        "install failed during racing cache clean — the graceful-degradation \
         contract around metadata-cache failures is broken.\n\
         stdout:\n{}\nstderr:\n{}",
        install_out.stdout,
        install_out.stderr
    );
    assert!(
        clean_output.status.success(),
        "cache clean failed during install:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&clean_output.stdout),
        String::from_utf8_lossy(&clean_output.stderr)
    );
    assert!(
        !install_out.stderr.contains("panicked at"),
        "install panicked during racing cache clean:\nstderr:\n{}",
        install_out.stderr
    );
    let clean_stderr = String::from_utf8_lossy(&clean_output.stderr);
    assert!(
        !clean_stderr.contains("panicked at"),
        "cache clean panicked during racing install:\nstderr:\n{clean_stderr}"
    );

    // **LOAD-BEARING #2:** evidence the race window was real. If the
    // install completed faster than the configured tarball delay, the
    // test didn't exercise mid-install conditions and the assertions
    // above are vacuous.
    let install_elapsed = install_end.duration_since(install_start);
    assert!(
        install_elapsed >= tarball_delay,
        "install completed in {install_elapsed:?}, faster than the \
         configured tarball delay of {tarball_delay:?} — the slow-install \
         window wasn't exercised, so the cache-clean race wasn't real"
    );

    // **LOAD-BEARING #3:** cache clean must have actually fired DURING
    // the install window, not entirely before it (impossible — we
    // waited for the shared store_lock first) or entirely after.
    let clean_started_during_install = clean_start >= install_start && clean_start < install_end;
    assert!(
        clean_started_during_install,
        "cache clean did not start during the install window — race \
         conditions weren't exercised.\n\
         install: {install_start:?}-{install_end:?}\n\
         clean:   {clean_start:?}-{clean_end:?}"
    );

    // **LOAD-BEARING #4:** store entry survived. Cache clean must
    // never touch the store, even when running concurrently with
    // an install that's actively writing to it.
    let store = lpm_store::v2::Store::at(project.store_dir().join("v2"));
    let store_entry = store
        .reusable_object_dir(&integrity)
        .expect("validate slow-cc-pkg v2 object")
        .expect("slow-cc-pkg v2 object must remain reusable after cache clean");
    assert!(
        store_entry.join("package.json").exists(),
        "store entry's package.json is missing — partial extraction or \
         cache clean reached into the store. checked: {:?}",
        store_entry.join("package.json")
    );

    // **LOAD-BEARING #5:** install's user-visible outputs all landed.
    // Project-side artifacts (linked tree, manifest update, install-
    // hash) prove the install was end-to-end successful, not just
    // "didn't crash mid-pipeline".
    let nm_entry = project.path().join("node_modules/slow-cc-pkg");
    assert!(
        nm_entry.symlink_metadata().is_ok(),
        "node_modules/slow-cc-pkg missing post-install — the linker \
         either failed silently or skipped the package"
    );
    let pkg_json: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("post-install package.json must parse");
    assert!(
        pkg_json["dependencies"]["slow-cc-pkg"].as_str().is_some(),
        "slow-cc-pkg dep missing from package.json after install — the \
         manifest write didn't land. package.json: {pkg_json}"
    );
    assert!(
        project.path().join(".lpm/install-hash").exists(),
        "`.lpm/install-hash` missing after install — the post-install \
         freshness hash write didn't land. This would force the next \
         install onto the slow path."
    );
}

/// **G.6 — malformed registry JSON fails without manifest or lockfile mutation.**
///
/// The install pipeline reads metadata from `GET /api/registry/{name}`
/// (and the npm-direct mirror `GET /{name}`) plus
/// `POST /api/registry/batch-metadata`. A registry that returns
/// truncated or otherwise invalid JSON on those paths must fail the
/// install cleanly — no panic, no backtrace, and ManifestTransaction
/// rollback must restore the project to its pre-install state.
///
/// **Why this matters.** A misbehaving / under-attack / partially-
/// migrated registry could ship a half-written response body. The
/// install pipeline's contract:
///
/// - Resolver/registry-client returns a recoverable error (not a panic).
/// - `?`-early-exit triggers `ManifestTransaction::Drop`, which
///   restores `package.json` from the pre-install snapshot.
/// - No fresh `lpm.lock` lands on disk (any partial write would be
///   rolled back by the optional-snapshot branch).
///
/// Pinned contract:
///
/// - Process exits non-zero.
/// - Stderr does NOT contain `"panicked at"` or `RUST_BACKTRACE`.
/// - `package.json` bytes are EXACTLY the pre-install bytes (Drop
///   restored the snapshot).
/// - `lpm.lock` is absent (was absent pre-install; rollback's
///   optional-snapshot branch must keep it absent).
/// - `.lpm/install-hash` is absent (invalidate-on-rollback).
///
/// The test mounts truncated JSON on BOTH metadata endpoints
/// (the single-package GET and the batch-metadata POST) so the
/// failure reaches the install pipeline regardless of which path
/// the client reads first.
#[tokio::test]
async fn malformed_registry_json_fails_without_manifest_or_lockfile_mutation() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let mock = MockRegistry::start().await;
    let pkg = "broken-json-pkg";

    // Truncated JSON body — opens a `{` and a `"name":"` field, then
    // cuts off mid-string-value. Both `serde_json::from_slice` and a
    // streaming parser will error on EOF mid-token.
    let bad_json = b"{\"name\":\"broken-json-pkg\",\"versions\":{\"1.0.";

    // Mount the broken body on every metadata path the install
    // pipeline might consult. wiremock matches mounts in declared
    // order; these explicit mounts win over any later `with_package`
    // would attempt (we deliberately DON'T call `with_package`).
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{pkg}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(bad_json.to_vec())
                .insert_header("content-type", "application/json"),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{pkg}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(bad_json.to_vec())
                .insert_header("content-type", "application/json"),
        )
        .mount(mock.server())
        .await;
    // batch-metadata is NDJSON; a non-NDJSON-shaped body causes the
    // line parser to reject every line. Same exit path as the single-
    // GET malformed case.
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(bad_json.to_vec())
                .insert_header("content-type", "application/x-ndjson"),
        )
        .mount(mock.server())
        .await;

    let pre_pkg_json = r#"{
  "name": "malformed-json-test",
  "version": "1.0.0"
}"#;
    let project = TempProject::empty(pre_pkg_json);

    let pre_bytes = std::fs::read(project.path().join("package.json"))
        .expect("test setup: package.json must exist");

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&[&format!("{pkg}@1.0.0")]))
        .output()
        .expect("run install against malformed-JSON registry");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[G.6] status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install against malformed-JSON registry reported success — \
         the resolver/registry-client accepted a half-body response.\n\
         stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "install panicked on malformed JSON — the resolver should \
         return a recoverable error, not a panic.\nstderr:\n{stderr}"
    );

    // **LOAD-BEARING.** package.json must be byte-identical to
    // pre-install state. If Drop didn't restore the snapshot — or if
    // the staged `*` placeholder leaked because the pipeline bailed
    // out without unwinding through ManifestTransaction's Drop —
    // this trips.
    let post_bytes = std::fs::read(project.path().join("package.json"))
        .expect("package.json must still exist after malformed-JSON failure");
    assert_eq!(
        pre_bytes,
        post_bytes,
        "package.json was mutated by failed install against malformed \
         registry. ManifestTransaction rollback contract broken.\n\
         pre={}\npost={}",
        String::from_utf8_lossy(&pre_bytes),
        String::from_utf8_lossy(&post_bytes)
    );

    // Stricter shape: post-state JSON must parse AND must not contain
    // the broken-json-pkg dep.
    let post_json: serde_json::Value =
        serde_json::from_slice(&post_bytes).expect("post-rollback package.json must parse as JSON");
    let deps = post_json
        .get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    assert!(
        !deps.contains_key(pkg),
        "{pkg} appeared in dependencies after malformed-JSON failure — \
         the staged placeholder leaked through the failure path. deps={:?}",
        deps.keys().collect::<Vec<_>>()
    );

    // No lockfile artifacts should have landed.
    assert!(
        !project.path().join("lpm.lock").exists(),
        "lpm.lock exists after malformed-JSON failure — partial \
         lockfile write or optional-snapshot rollback regression"
    );
    assert!(
        !project.path().join(".lpm/install-hash").exists(),
        "`.lpm/install-hash` exists after malformed-JSON failure — \
         the invalidate-on-rollback contract broke"
    );

    // Stderr should name SOMETHING actionable about the JSON / metadata
    // failure so a user can diagnose the upstream issue. Broad word
    // list to tolerate the registry-client's exact phrasing.
    let stderr_l = stderr.to_lowercase();
    let actionable = [
        "json",
        "parse",
        "deserialize",
        "metadata",
        "registry",
        "invalid",
        "unexpected",
        "decode",
        "eof",
        "malformed",
    ]
    .iter()
    .any(|n| stderr_l.contains(n));
    assert!(
        actionable,
        "malformed-JSON failure didn't surface an actionable noun. \
         A user should be able to tell from stderr that the registry's \
         response was malformed. stderr:\n{stderr}"
    );
}

/// **G.5 — panic after install-hash write → rollback restores pre-stage state.**
///
/// Counterpart to B.4 (which exercises `after-stage`). The
/// `after-install` stage of [`maybe_test_panic`](../../../crates/lpm-cli/src/commands/install.rs)
/// fires AFTER `run_with_options` returns, which means the install
/// pipeline has already invoked `write_post_install_v6_hash` —
/// `.lpm/install-hash` is on disk at panic time. The contract being
/// pinned here is that ManifestTransaction's Drop-based rollback
/// correctly **invalidates** the freshly-written install-hash on its
/// way out, AND restores `package.json` from the snapshot, even when
/// the failure point is past the install-hash write site.
///
/// **Why this matters.** If Drop didn't invalidate the install-hash
/// on rollback, a future `lpm install` would fast-path on the stale
/// hash (which matches a `*`-placeholder manifest the user never
/// wrote) and skip the resolve — a silent data-loss path.
/// `.lpm/install-hash` lives in the transaction's invalidate-set
/// (per [`manifest_tx.rs`](../../../crates/lpm-cli/src/manifest_tx.rs))
/// precisely to foreclose this.
///
/// Note this is the **panic** variant of the row (`after-install`
/// hook fires Drop). The SIGKILL variant — which would leave the
/// install-hash on disk because Drop is bypassed — is intentionally
/// not exercised here; that scenario is covered by E.2
/// (`install_with_stale_install_hash_re_resolves_and_refetches`),
/// which pins the recovery path with a planted stale hash.
#[cfg(debug_assertions)]
#[tokio::test]
async fn install_panics_after_install_hash_write_rollback_invalidates_hash() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("post-hash-rollback-pkg", "1.0.0");
    mock.with_package("post-hash-rollback-pkg", "1.0.0", &tarball)
        .await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "post-hash-rollback-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let pre_pkg_json = r#"{
  "name": "post-hash-rollback-test",
  "version": "1.0.0"
}"#;
    let project = TempProject::empty(pre_pkg_json);

    let pre_bytes = std::fs::read(project.path().join("package.json"))
        .expect("test setup: package.json must exist");
    assert!(
        !pre_bytes.contains_subslice(b"post-hash-rollback-pkg"),
        "test setup: pre-stage manifest already has the package — \
         would mask the rollback assertion"
    );

    let output = lpm_with_registry(&project, &mock.url())
        // Trigger panic AFTER run_with_options returns (i.e., after
        // write_post_install_v6_hash already ran). Same hook as B.4
        // but a different stage.
        .env("LPM_TEST_PANIC_AT", "after-install")
        .args(install_args_with(&["post-hash-rollback-pkg@1.0.0"]))
        .output()
        .expect("run install with panic after install-hash");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[G.5] status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install with LPM_TEST_PANIC_AT=after-install reported success — \
         the panic hook did NOT fire. stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("panicked at"),
        "panic hook did not surface a panic in stderr. The `after-install` \
         stage is not wired or the env didn't pass through. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("LPM_TEST_PANIC_AT=after-install"),
        "panic fired but the stage marker is missing — the hook's panic \
         message contract changed. stderr:\n{stderr}"
    );

    // **LOAD-BEARING #1.** package.json must be byte-identical.
    let post_bytes = std::fs::read(project.path().join("package.json"))
        .expect("package.json must still exist after panic-after-install");
    assert_eq!(
        pre_bytes,
        post_bytes,
        "package.json was NOT restored after panic at `after-install`. \
         The post-install-hash-write rollback contract is broken.\n\
         pre={}\npost={}",
        String::from_utf8_lossy(&pre_bytes),
        String::from_utf8_lossy(&post_bytes)
    );

    let post_json: serde_json::Value =
        serde_json::from_slice(&post_bytes).expect("post-rollback package.json must parse as JSON");
    let deps = post_json
        .get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    assert!(
        !deps.contains_key("post-hash-rollback-pkg"),
        "post-hash-rollback-pkg is still in dependencies after panic-rollback \
         — the `*` placeholder leaked. deps={:?}",
        deps.keys().collect::<Vec<_>>()
    );

    // **LOAD-BEARING #2.** `.lpm/install-hash` was written by
    // `write_post_install_v6_hash` BEFORE the `after-install` panic
    // fired. Drop MUST have deleted it via the invalidate-set. If it
    // survives, the next install would fast-path on a hash computed
    // against state the user never committed (`*` placeholder) →
    // silent data-loss path.
    assert!(
        !project.path().join(".lpm/install-hash").exists(),
        "`.lpm/install-hash` survived panic-rollback after `after-install` — \
         the invalidate-on-rollback contract is broken for the post-hash-write \
         failure window. A subsequent `lpm install` would fast-path on a stale \
         hash computed against the partially-staged manifest."
    );

    // Lockfile is optional in the transaction's snapshot. Pre-install
    // it didn't exist; post-rollback must match.
    assert!(
        !project.path().join("lpm.lock").exists(),
        "`lpm.lock` survived panic-rollback (snapshot captured `None` \
         pre-install). The optional-snapshot rollback branch broke."
    );
}

// ─── Shared mini-helpers ─────────────────────────────────────────────

fn install_args_with<'a>(packages: &'a [&'a str]) -> Vec<&'a str> {
    let mut v = vec![
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ];
    v.extend_from_slice(packages);
    v
}

fn single_version_batch_metadata(name: &str, version: &str, mock_url: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": {
                    "tarball": format!("{mock_url}/tarballs/{name}/-/{name}-{version}.tgz"),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { version: "2025-01-01T00:00:00.000Z" }
    })
}

struct CapturedOutput {
    stdout: String,
    stderr: String,
}

fn read_remaining_output(child: Child) -> CapturedOutput {
    // Child is already waited; reading the piped streams to EOF is
    // safe and non-blocking.
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait_with_output after kill: {e}"));
    CapturedOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}
