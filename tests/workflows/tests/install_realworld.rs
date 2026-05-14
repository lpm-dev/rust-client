//! Real-world install-pipeline coverage at production scale.
//!
//! Item 5 §1 of `private/test-coverage-followup-plan.md`. Companion
//! to `install_real_registry.rs` (which covers single-package smoke
//! tests against Verdaccio). The tests here drive `lpm install`
//! against the [`realworld-nextjs`](../../fixtures/realworld-nextjs/)
//! fixture, whose `package.json` resolves to ~28 transitive packages
//! (empirically measured 2026-05-14) covering Next.js 14, React 18,
//! TypeScript 5, and `@types/*` shapes — including platform-specific
//! optional deps (`@next/swc-*`).
//!
//! **Why a separate file.** `install_real_registry.rs` is for tight,
//! single-package contracts (lockfile-source recording, bin-shim
//! parity with npm, the lodash byte-equivalence diff). The realworld
//! fixture is two orders of magnitude bigger and is paid for at the
//! file level — pulling it into the existing file would slow down
//! the single-package smoke tests on every parallel-nextest run.
//!
//! **Budget assertions are gated behind `LPM_BUDGET_GATE=1`.**
//! Wall-clock and memory budgets are CI-flake-prone without a
//! calibrated reference machine — runner CPU speed, network latency
//! to npmjs, and Verdaccio start-up overhead all push the cold-install
//! number around by ±5-10 seconds across hosts. The strategy:
//!
//! - The test ALWAYS measures cold wall-clock, warm wall-clock, and
//!   cold-install peak RSS, and logs them to stderr.
//! - **When `LPM_BUDGET_GATE=1`** (set on a calibrated reference
//!   machine — currently this dev box, future the weekly
//!   `realworld-audit` workflow's runner), the test ALSO asserts
//!   each measurement against a budget derived from the calibration
//!   methodology in [tests/fixtures/realworld-nextjs/README.md](../../fixtures/realworld-nextjs/README.md#calibration).
//! - **Without the gate**, the assertions are skipped — the test
//!   passes on any host that successfully runs the install.
//!
//! **Item 5 §2-§4 status (2026-05-14):** the §2 cold-wall-clock budget,
//! §3 warm-wall-clock budget, and §4 memory budget are all wired below,
//! gated as described, and calibrated from N=6 dev-box runs (cold
//! 13.8-16.6s, warm 8.5-8.8ms, peak RSS 749-884 MB). Numbers are
//! intentionally specific to the calibrated host; ports to other
//! reference machines should re-derive following the same methodology.
//!
//! **Memory measurement.** Cold-install peak RSS comes from wrapping
//! the lpm-rs binary in `/usr/bin/time -l` (macOS) or `-v` (Linux)
//! and parsing the peak-RSS line from its stderr. POSIX-only —
//! Windows runs skip the memory measurement and any associated
//! assertion. Same `parse_peak_rss` shape can be lifted to
//! `support/mod.rs` if a second test needs it.
//!
//! **Verdaccio-npm parity** (§3 of the original surface) is NOT
//! covered here — the bin-package and lodash diff tests in
//! `install_real_registry.rs` already pin the manager-equivalence
//! contract. Expanding to a 100+ package tree would multiply the
//! comparison surface without adding signal.
//!
//! **Skip-and-warn posture.** Verdaccio is started via `npx
//! --yes verdaccio@<version>`, which requires (a) `npx` on PATH and
//! (b) network access to fetch Verdaccio + the proxied packages
//! from `registry.npmjs.org`. Hosts that fail either prerequisite
//! should produce a clean skip, not a test failure — same posture
//! as the existing `flow_lpm_vs_npm_install_lodash_diff_within_documented_tolerance`.

mod support;

use std::process::Output;
use std::time::{Duration, Instant};

use support::verdaccio::VerdaccioRegistry;
use support::{TempProject, lpm};

// ─── Budget calibration ─────────────────────────────────────────────
//
// Numbers calibrated 2026-05-14 from N=6 dev-box runs on M-series
// macOS against the realworld-nextjs fixture pinned at the versions
// in `tests/fixtures/realworld-nextjs/package.json`. See the README
// at that path for the derivation methodology.
//
// Re-derive these constants when:
//   - The fixture's pinned versions change (resolved tree size shifts).
//   - The reference machine changes (different CPU/network profile).
//   - A measured runtime trend exits the budget — at which point either
//     fix the regression OR re-baseline and bump the constant with a
//     note in the README's "Calibration history".

/// Cold-install wall-clock budget. Calibrated max 16.6s × 1.5 → 25s.
const COLD_INSTALL_BUDGET: Duration = Duration::from_secs(25);

/// Warm-install (install-hash fast path) budget. Calibrated max
/// 8.8ms × ~3 → 25ms. The fast path is a pure hash-equality check, so
/// the budget is dominated by process-startup overhead.
const WARM_INSTALL_BUDGET: Duration = Duration::from_millis(25);

/// Peak-RSS budget for the cold install subprocess, in bytes. Calibrated
/// max 884 MiB × ~1.7 → 1500 MiB. The install pipeline buffers
/// in-flight tarballs + extracted bytes during parallel fetches, which
/// dominates RSS.
const COLD_PEAK_RSS_BUDGET_BYTES: u64 = 1_500 * 1024 * 1024;

/// Set `LPM_BUDGET_GATE=1` on a calibrated reference machine to enable
/// the budget assertions below. Without it the measurements still log
/// to stderr; only the assert-against-budget step is skipped.
fn budget_gate_enabled() -> bool {
    std::env::var("LPM_BUDGET_GATE").as_deref() == Ok("1")
}

/// Run `lpm install` against the configured Verdaccio mirror inside
/// the project directory.
///
/// Returns the captured `Output` so the caller can decide whether to
/// assert success or skip-and-warn. Used for the warm-install step
/// where memory measurement isn't needed (the install-hash fast path
/// runs entirely in the parent process and doesn't allocate much).
fn run_install(project: &TempProject) -> Output {
    lpm(project)
        // LPM_NPM_ROUTE=proxy is the test-harness default; clearing
        // it lets the project's .npmrc steer the registry choice
        // (Verdaccio in this case). Same as the existing real-registry
        // smoke tests.
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args([
            "install",
            "--allow-new",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install against verdaccio")
}

/// Run `lpm install` wrapped in `/usr/bin/time -l/-v` so we can read
/// peak resident-set size from `time(1)`'s stderr report. Returns the
/// captured `Output` plus an optional peak-RSS in bytes.
///
/// Returns `Ok(None)` for the RSS value on platforms where the wrapper
/// isn't supported (Windows) or when the `time(1)` output couldn't be
/// parsed — callers should treat that case as "no memory budget
/// assertion possible on this host" rather than as a test failure.
///
/// The captured stdout/stderr are the lpm-rs subprocess's own output
/// (mostly stderr — `time(1)`'s report is appended to stderr after
/// the wrapped binary's output, so the parser walks the trailing lines).
#[cfg(unix)]
fn run_install_under_time(project: &TempProject) -> (Output, Option<u64>) {
    use std::process::{Command, Stdio};
    let bin = assert_cmd::cargo::cargo_bin("lpm-rs");
    let mut cmd = Command::new("/usr/bin/time");

    #[cfg(target_os = "macos")]
    cmd.arg("-l");
    #[cfg(target_os = "linux")]
    cmd.arg("-v");

    cmd.arg(&bin);
    cmd.arg("install")
        .arg("--allow-new")
        .arg("--no-security-summary")
        .arg("--no-skills")
        .arg("--no-editor-setup");
    cmd.current_dir(project.path());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // Mirror the env-isolation set the `lpm()` / `lpm_spawnable()`
    // helpers apply. We can't call `apply_lpm_env` directly (private
    // to `support/mod.rs`), so we approximate by reading the env from
    // a parallel `lpm_spawnable` build and copying it onto our
    // `time`-wrapped command. This keeps the two helpers in sync
    // through `apply_lpm_env`, even though we bypass it structurally.
    let mut env_source = support::lpm_spawnable(project);
    env_source.env_remove("LPM_NPM_ROUTE");
    env_source.env_remove("LPM_TOKEN");
    // `get_envs` yields (OsStr, Option<&OsStr>); None means "remove",
    // Some means "set". Apply both correctly.
    for (k, v) in env_source.get_envs() {
        match v {
            Some(value) => {
                cmd.env(k, value);
            }
            None => {
                cmd.env_remove(k);
            }
        }
    }

    let output = cmd
        .output()
        .expect("failed to run lpm install under /usr/bin/time");

    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let peak_rss = parse_peak_rss(&stderr_str);
    (output, peak_rss)
}

#[cfg(not(unix))]
fn run_install_under_time(project: &TempProject) -> (Output, Option<u64>) {
    // No `/usr/bin/time` on Windows. Fall back to a plain install
    // and report None for RSS — the memory-budget assertion will
    // be skipped on this platform.
    (run_install(project), None)
}

/// Parse peak resident-set size in bytes from `time -l` (macOS) or
/// `time -v` (Linux GNU) output. Returns `None` if no recognizable
/// line is found.
#[cfg(unix)]
fn parse_peak_rss(time_output: &str) -> Option<u64> {
    for line in time_output.lines() {
        let trimmed = line.trim();

        // macOS BSD `time -l`: `<bytes>  maximum resident set size`
        #[cfg(target_os = "macos")]
        {
            if let Some(rest) = trimmed.strip_suffix("maximum resident set size") {
                let bytes_str = rest.trim();
                if let Ok(bytes) = bytes_str.parse::<u64>() {
                    return Some(bytes);
                }
            }
        }

        // GNU `time -v`: `Maximum resident set size (kbytes): <kb>`
        #[cfg(target_os = "linux")]
        {
            if let Some(rest) = trimmed.strip_prefix("Maximum resident set size (kbytes):")
                && let Ok(kb) = rest.trim().parse::<u64>()
            {
                return Some(kb.saturating_mul(1024));
            }
        }

        // Silence unused-variable warning when neither cfg applies
        // (e.g., other unix targets such as freebsd) — fall through
        // to None.
        let _ = trimmed;
    }
    None
}

/// **Item 5 §1 — realworld Next.js install succeeds end-to-end via Verdaccio.**
///
/// The fixture's `package.json` pins exact versions of `next@14.2.13`,
/// `react@18.3.1`, `react-dom@18.3.1`, `typescript@5.6.3`, and three
/// `@types/*` packages. Resolving that closure against a real npm
/// upstream exercises the install pipeline at production scale: the
/// resolver walks ~28 transitive deps (empirically measured), the
/// registry client batches metadata fetches, the fetch pipeline
/// downloads tarballs in parallel, the extractor unpacks each into
/// the content-addressed store, the linker materializes
/// `node_modules/`, and the install-hash gets written.
///
/// **What's asserted unconditionally:** end-to-end success — every
/// stage of the pipeline completes, the lockfile is parseable, the
/// direct deps materialize in `node_modules/`, and
/// `.lpm/install-hash` lands.
///
/// **What's asserted under `LPM_BUDGET_GATE=1` (Item 5 §2-§4):**
///   - Cold install ≤ `COLD_INSTALL_BUDGET` (25 s) — catches
///     resolver/fetch/extract regressions that double the wall-clock.
///   - Warm install ≤ `WARM_INSTALL_BUDGET` (25 ms) — catches a
///     regression in the install-hash fast-path that falls back to
///     the slow path even when the fingerprint matches.
///   - Peak cold-install RSS ≤ `COLD_PEAK_RSS_BUDGET_BYTES` (1.5 GiB)
///     — catches a memory regression that loads the whole metadata
///     graph or buffers every tarball simultaneously.
///
/// All three measurements are logged to stderr regardless of the
/// gate so calibration data is always available.
///
/// **Platform-specific optional deps.** Next.js declares one
/// `@next/swc-*` binary per `(os, cpu)` pair as `optionalDependencies`.
/// The resolver MUST pick the entry matching the current platform
/// and skip the others without failing — a regression that hard-
/// requires every optional dep would break this install on every
/// platform. The implicit "install succeeds" assertion catches that.
#[tokio::test]
async fn install_realworld_nextjs_fixture_succeeds_through_verdaccio() {
    // Pre-flight: refuse to start Verdaccio if we can clearly tell
    // it won't work (no `npx` on PATH). The `VerdaccioRegistry::start`
    // path internally retries and panics if Verdaccio doesn't come
    // up in budget; that's appropriate when the test is REQUIRED to
    // run, but for this realworld test we want a clean skip-and-warn
    // when the runner lacks network/tooling.
    if !npx_is_available() {
        eprintln!(
            "SKIP install_realworld_nextjs_fixture_succeeds_through_verdaccio: \
             `npx --version` failed (npx not on PATH?)"
        );
        return;
    }

    let registry = VerdaccioRegistry::start().await;

    let project = TempProject::from_fixture("realworld-nextjs");
    registry.write_project_npmrc(project.path());

    // Sanity: fixture loaded into the temp project. If `from_fixture`
    // ever changes its semantics (e.g., starts auto-installing), this
    // assertion catches it before the install timing is recorded.
    assert!(
        project.path().join("package.json").exists(),
        "fixture copy must materialize package.json at the project root"
    );
    let manifest: serde_json::Value = serde_json::from_str(&project.read_file("package.json"))
        .expect("fixture package.json must parse");
    assert_eq!(
        manifest["dependencies"]["next"].as_str(),
        Some("14.2.13"),
        "fixture must pin next@14.2.13 — version drift in the fixture \
         would invalidate the docstring's transitive-count assumption. \
         Got: {manifest}"
    );

    let cold_start = Instant::now();
    let (output, peak_rss_bytes) = run_install_under_time(&project);
    let cold_elapsed = cold_start.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let peak_rss_mib = peak_rss_bytes.map(|b| b as f64 / (1024.0 * 1024.0));
    eprintln!(
        "[realworld-nextjs] cold_install_elapsed={cold_elapsed:?} \
         peak_rss={} status={:?}\n\
         stdout (first 4KB):\n{:.4096}\n\
         stderr (first 4KB):\n{:.4096}",
        peak_rss_mib
            .map(|m| format!("{m:.1} MiB"))
            .unwrap_or_else(|| "<unavailable>".into()),
        output.status,
        stdout,
        stderr,
    );

    assert!(
        output.status.success(),
        "realworld-nextjs install through Verdaccio failed.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Direct deps must materialize. These are the user-visible
    // packages the manifest declares; a regression that resolved
    // them but failed to link would trip these.
    for direct_dep in ["next", "react", "react-dom"] {
        let dep_dir = project.path().join("node_modules").join(direct_dep);
        assert!(
            dep_dir.exists(),
            "node_modules/{direct_dep} missing after realworld install — \
             the linker did not materialize this direct dep. checked: {dep_dir:?}"
        );
        let dep_pkg_json = dep_dir.join("package.json");
        assert!(
            dep_pkg_json.exists(),
            "node_modules/{direct_dep}/package.json missing — the package \
             dir exists but is empty/partial. checked: {dep_pkg_json:?}"
        );
    }

    // Tree-scale heuristic: the realworld fixture's RESOLVED tree
    // (= lockfile packages count) is empirically ~28 packages as of
    // 2026-05-14 (Next.js 14.2.13 + React 18.3.1 + TypeScript 5.6.3 +
    // @types/*). A regression that silently dropped transitive deps
    // would leave the lockfile with only the direct deps (≤7).
    //
    // The 25-entry floor sits below the measured count to absorb
    // patch-level reshuffles (e.g., a Next.js patch consolidating
    // two helper packages into one) without falsely tripping the
    // test. It still cleanly fails on the "dropped half the tree"
    // class of regression.
    //
    // **The lockfile check is the load-bearing one** — the
    // node_modules top-level count below is smaller because the
    // isolated linker (the workflow-tier default per `LpmRoot`
    // setup) hoists only some packages to the root and parks the
    // rest in `node_modules/.lpm/`. The exact split depends on the
    // linker's heuristics, not the resolver's output.
    let lockfile_path = project.path().join("lpm.lock");
    assert!(
        lockfile_path.exists(),
        "lpm.lock missing after install — the lockfile-write path \
         did not complete"
    );
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .expect("lpm.lock must parse after a successful realworld install");
    let lockfile_pkg_count = lockfile.packages.len();
    assert!(
        lockfile_pkg_count >= 25,
        "lpm.lock has only {lockfile_pkg_count} package entries after realworld \
         install — expected ~28 to mirror the resolved tree. A silent dep-drop \
         regression in the resolver is the likely culprit."
    );

    // Secondary sanity: node_modules top-level entries. With the
    // isolated linker the count is smaller than the lockfile total
    // (rest live under `node_modules/.lpm/`). Empirically ~24 entries
    // for this fixture on 2026-05-14. The 18-entry floor protects
    // against a regression that dropped the LINKER half of the
    // pipeline (lockfile correct, link tree empty).
    let nm_count = std::fs::read_dir(project.path().join("node_modules"))
        .expect("node_modules must be readable after install")
        .filter_map(|e| e.ok())
        .filter(|e| {
            // Skip `.lpm`, `.bin`, etc. — only real package dirs.
            e.file_name()
                .to_str()
                .map(|s| !s.starts_with('.'))
                .unwrap_or(false)
        })
        .count();
    assert!(
        nm_count >= 18,
        "node_modules has only {nm_count} top-level package entries after \
         realworld install — expected ~24 (isolated-linker shape) for this \
         fixture's resolved tree. The lockfile size was {lockfile_pkg_count} \
         packages, so the resolver succeeded — the linker is the likely \
         regression site."
    );

    // Install-hash landed. Proves the post-install fast-path cache
    // is consistent with the install just performed, so a follow-up
    // `lpm install` will short-circuit on the warm path.
    assert!(
        project.path().join(".lpm/install-hash").exists(),
        "`.lpm/install-hash` missing after realworld install — the \
         freshness-cache write did not land, forcing the next install \
         onto the slow path"
    );

    // No panic / backtrace in stderr — the install completed cleanly,
    // not as a partial-success-with-recovered-error.
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "realworld install emitted a panic / backtrace in stderr — \
         the pipeline recovered from a panic that should never fire. \
         stderr:\n{stderr}"
    );

    // Bonus diagnostic: warm-install timing. A second `lpm install`
    // on the same project with the store already populated should
    // hit the install-hash fast path and complete in milliseconds.
    // We record it to stderr so a future budget pass has data without
    // running this expensive test setup twice.
    let warm_start = Instant::now();
    let warm_output = run_install(&project);
    let warm_elapsed = warm_start.elapsed();
    assert!(
        warm_output.status.success(),
        "warm install (second run) failed — the install-hash fast \
         path or store re-link broke.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&warm_output.stdout),
        String::from_utf8_lossy(&warm_output.stderr)
    );
    eprintln!(
        "[realworld-nextjs] warm_install_elapsed={warm_elapsed:?}\n\
         cold/warm ratio (informational): {:.1}x",
        cold_elapsed.as_secs_f64() / warm_elapsed.as_secs_f64().max(0.001),
    );

    // ── Budget assertions (gated) ─────────────────────────────────
    //
    // Without `LPM_BUDGET_GATE=1`, the measurements above logged to
    // stderr but the assertions below are skipped. With the gate on,
    // each measurement must fall under its calibrated budget — see
    // the constants at the top of this file for derivation.
    if !budget_gate_enabled() {
        eprintln!(
            "[realworld-nextjs] LPM_BUDGET_GATE not set — skipping budget \
             assertions (cold ≤ {:?}, warm ≤ {:?}, peak RSS ≤ {} MiB).",
            COLD_INSTALL_BUDGET,
            WARM_INSTALL_BUDGET,
            COLD_PEAK_RSS_BUDGET_BYTES / (1024 * 1024),
        );
        return;
    }

    eprintln!("[realworld-nextjs] LPM_BUDGET_GATE=1 — asserting budgets.");

    assert!(
        cold_elapsed <= COLD_INSTALL_BUDGET,
        "cold-install wall-clock exceeded budget: measured {cold_elapsed:?} > \
         budget {COLD_INSTALL_BUDGET:?}. Either the install pipeline regressed \
         (resolver / fetch / extract / link took longer) or the reference \
         machine's profile drifted (recalibrate per the README methodology)."
    );
    assert!(
        warm_elapsed <= WARM_INSTALL_BUDGET,
        "warm-install wall-clock exceeded budget: measured {warm_elapsed:?} > \
         budget {WARM_INSTALL_BUDGET:?}. The install-hash fast path's \
         hash-equality check should be process-startup-bound; a regression \
         here likely means the fast path is falling through to the slow path."
    );
    match peak_rss_bytes {
        Some(rss) => {
            assert!(
                rss <= COLD_PEAK_RSS_BUDGET_BYTES,
                "cold-install peak RSS exceeded budget: measured {} MiB > \
                 budget {} MiB. The install pipeline regressed memory: candidate \
                 causes include buffering every tarball simultaneously, loading \
                 the metadata graph in one allocation, or a Verdaccio-side \
                 inflation that the wrapper attributes to our subprocess.",
                rss / (1024 * 1024),
                COLD_PEAK_RSS_BUDGET_BYTES / (1024 * 1024)
            );
        }
        None => {
            // No `/usr/bin/time` available (Windows, or parse failed).
            // Don't fail the budget assertion — surface the gap so a
            // reference-machine setup can fix it.
            eprintln!(
                "[realworld-nextjs] WARNING: peak-RSS measurement unavailable \
                 on this platform — memory budget assertion skipped even \
                 though LPM_BUDGET_GATE=1 was set."
            );
        }
    }
}

fn npx_is_available() -> bool {
    std::process::Command::new("npx")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
