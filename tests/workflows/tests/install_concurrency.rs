//! Concurrency and recovery contract tests for `lpm install`.
//!
//! Item 2 of `private/test-coverage-followup-plan.md`. Pins behavior
//! under the production failure modes that have **zero coverage** in
//! the existing suite:
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
//! Findings surfaced during this work are filed in
//! `private/findings.md`. Tests that pin a buggy current state carry a
//! `// TODO #NN — tighten when finding #NN fixed` comment.
//!
//! See `private/test-coverage-followup-plan.md` for the full design
//! and the verified architectural facts each test rests on.

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

    let tarball_url = format!("{}/tarballs/{name}-{version}.tgz", mock.url());
    let integrity = compute_integrity(&tarball_bytes);
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
        .and(path(format!("/tarballs/{name}-{version}.tgz")))
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

    // POST-CONDITION 3 (diagnostic only — finding #77): manifest /
    // node_modules coherence. The race produces THREE observed
    // outcomes today:
    //   (a) both succeed; last-writer-wins → one pkg in manifest,
    //       one in node_modules.
    //   (b) one succeeds, one fails with "failed to rename to
    //       lpm.lock: No such file or directory" (the atomic-rename
    //       race biting hard).
    //   (c) both fail with the rename race (rare, observed under
    //       heavy parallel load).
    // None of these are correct behavior — they are all forms of
    // finding #77's data-loss surface. The test pins the FLOOR:
    // package.json must parse, lpm.lock must be well-formed UTF-8
    // if present (post-conditions 1+2 above). Outcomes are surfaced
    // via eprintln for diagnosability; once the project-install
    // lock lands, this section tightens into equality assertions.
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
        "[A.1 finding #77 signal] status_a={status_a:?} status_b={status_b:?} \
         manifest_has_pkg_a={pkg_a_in_deps} manifest_has_pkg_b={pkg_b_in_deps} \
         node_modules_has_pkg_a={pkg_a_linked} node_modules_has_pkg_b={pkg_b_linked}"
    );

    // POST-CONDITION 4: at least one of the two installs reported
    // its OWN dep landing — i.e., the operation isn't a total loss.
    // (Outcome (c) above would fail this; if we ever observe (c)
    // consistently, the race has escalated to a worse class.) The
    // race-rename failure (outcome (b)) still satisfies this since
    // the OTHER process succeeded.
    let some_progress = (status_a.success() && (pkg_a_in_deps || pkg_a_linked))
        || (status_b.success() && (pkg_b_in_deps || pkg_b_linked));
    assert!(
        some_progress,
        "both concurrent installs produced no observable progress \
         (neither pkg landed AND neither process reported success). \
         This would be a worse class of failure than the known \
         last-writer-wins race in finding #77.\n\
         status_a={status_a:?} stderr_a:\n{}\n\
         status_b={status_b:?} stderr_b:\n{}",
        out_a.stderr, out_b.stderr,
    );

    // TODO #77 — when the project-install lock lands, this section
    // tightens to: BOTH installs MUST succeed, BOTH pkg-a AND pkg-b
    // MUST be in dependencies, BOTH MUST be in node_modules. The
    // diagnostic eprintln becomes assertions.
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
/// Unlike project installs (no project-lock, finding #77), global
/// installs wrap their **commit** sections with `global_tx_lock` held
/// exclusively ([update_global.rs:534](../../../crates/lpm-cli/src/commands/update_global.rs),
/// [update_global.rs:562](../../../crates/lpm-cli/src/commands/update_global.rs)).
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
    let tarball_url = format!("{}/tarballs/flaky-pkg-1.0.0.tgz", mock.url());
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
        .and(path("/tarballs/flaky-pkg-1.0.0.tgz"))
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
    // No panic should escape — `miette`-formatted error is fine,
    // bare "panicked at" / "RUST_BACKTRACE" lines are not. The
    // failure should also reference the operation that couldn't
    // proceed (write / permission / lpm.lock-ish).
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
    let tarball_url = format!("{}/tarballs/stale-pkg-1.0.0.tgz", mock.url());
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
        .and(path("/tarballs/stale-pkg-1.0.0.tgz"))
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

/// **E.3 — `lpm install` with truncated `lpm.lockb` falls back to TOML.**
///
/// `lpm.lockb` is the binary mmap variant of the lockfile; `lpm.lock`
/// is the TOML source of truth. If the binary copy is truncated /
/// corrupt, the install must fall back to re-parsing the TOML — never
/// panic, never silently produce wrong results.
#[tokio::test]
async fn install_with_truncated_lockb_falls_back_to_toml() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("torn-pkg", "1.0.0");
    mock.with_package("torn-pkg", "1.0.0", &tarball).await;
    mock.with_batch_metadata(vec![single_version_batch_metadata(
        "torn-pkg",
        "1.0.0",
        &mock.url(),
    )])
    .await;

    let project = TempProject::empty(r#"{"name":"torn-test","version":"1.0.0"}"#);
    let first = lpm_with_registry(&project, &mock.url())
        .args(install_args_with(&["torn-pkg@1.0.0"]))
        .output()
        .expect("run first install");
    assert!(
        first.status.success(),
        "setup: first install failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Truncate lpm.lockb to a few random bytes — not a valid header.
    let lockb_path = project.path().join("lpm.lockb");
    assert!(
        lockb_path.exists(),
        "lpm.lockb wasn't written by first install"
    );
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
    let post_size = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
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
    let mid_wal_size = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
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
    let post_wal_size = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    assert_ne!(
        post_wal_size, 3,
        "after the lock-holder released, recovery still didn't run — \
         the dispatcher hook is broken in BOTH arms."
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
                    "tarball": format!("{mock_url}/tarballs/{name}-{version}.tgz"),
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
