//! Centralized `~/.lpm` path layer.
//!
//! Before this module, every crate that needed a machine-global path computed
//! it independently by reading `HOME` / `USERPROFILE` or calling
//! `dirs::home_dir()`, then joining `.lpm` + a crate-specific subpath. That
//! pattern made testing hard (no single injection point for a fake root) and
//! it let the global layout drift silently as new crates were added.
//!
//! Everything downstream now goes through [`LpmRoot`]. Paths are computed
//! once at startup (respecting `$LPM_HOME` for test / power-user overrides)
//! and passed around as a typed value.
//!
//! ## Layout
//!
//! ```text
//! <root>/
//!   bin/                          ← unix symlinks / Windows shim triples (on PATH)
//!   cache/
//!     metadata/                   ← registry metadata cache (lpm-registry)
//!     tasks/                      ← task cache (lpm-task)
//!     dlx/                        ← ephemeral dlx installs (lpm-runner) — was ~/.lpm/dlx-cache/
//!     mcp/                        ← verified MCP server runtime
//!     .clean.lock                 ← serializes concurrent `cache clean` ops
//!     .mcp.lock                   ← coordinates MCP refresh, execution, and cleanup
//!   engines/                      ← managed engine installs with preserved layouts
//!   store/
//!     v2/                         ← default virtual store
//!     v3/                         ← experimental file-CAS virtual store
//!     v1/                         ← explicit legacy rollback + upgrade compatibility
//!     .gc.lock                    ← serializes `store gc`
//!   global/
//!     manifest.toml               ← [packages.*] active + [pending.*] in-flight + [aliases] + [tombstones]
//!     build-state.json            ← pending blocked scripts (reuses lpm-cli BuildState shape)
//!     trusted-dependencies.json   ← GlobalTrustFile; parallel to project `package.json`'s lpm.trustedDependencies
//!     wal.jsonl                   ← framed write-ahead log for crash recovery
//!     .tx.lock                    ← fs2 advisory lock for install tx critical sections
//!     .tx.lock.pid                ← best-effort PID of current holder (unlinked on clean exit)
//!     installs/
//!       <name>@<ver>/             ← per-package isolated install root
//!         .lpm-install-ready      ← durable completeness marker
//!         lpm.lock
//!         node_modules/
//!         .lpm/
//! ```
//!
//! ## Testing
//!
//! Tests use [`LpmRoot::from_dir`] to inject a `tempfile::TempDir` as the
//! root. [`LpmRoot::from_env`] is strictly for production startup and is
//! the single canonical entry point for deciding where machine-global state
//! lives on a real user's machine.

use crate::LpmError;
use crate::color::Painted;
use std::path::{Path, PathBuf};

/// Filename of the durable completeness marker written into every
/// global install root. The marker is written **only after** the
/// extract / link / lockfile / bin-targets pipeline has fully
/// finished, and it is the load-bearing signal `is_ready()` and
/// `validate_install_root()` use to decide whether a partial install
/// is bootable.
///
/// Ephemeral (dlx) installs do NOT use this marker — they rely on the cheaper
/// `{package.json, node_modules/.bin}` pair plus mtime-based TTL.
pub const INSTALL_READY_MARKER: &str = ".lpm-install-ready";

/// Typed handle for the `~/.lpm/` directory tree.
///
/// Prefer passing `&LpmRoot` between crates over raw `PathBuf`s — it makes
/// call sites self-documenting and lets tests inject a fake home without
/// touching `$HOME` or `$LPM_HOME`.
#[derive(Debug, Clone)]
pub struct LpmRoot {
    home: PathBuf,
}

impl LpmRoot {
    /// Resolve the LPM root from the environment.
    ///
    /// Precedence:
    /// 1. `$LPM_HOME` if set (used by tests and power users)
    /// 2. `$HOME/.lpm` on Unix
    /// 3. `$USERPROFILE\.lpm` on Windows (via `dirs::home_dir`)
    ///
    /// Returns an error only when no home directory can be resolved, which
    /// on a sanely configured system is essentially never. This function
    /// performs **no** filesystem I/O and is safe to call from any command
    /// path, including read-only ones like `--help`.
    pub fn from_env() -> Result<Self, LpmError> {
        if let Ok(explicit) = std::env::var("LPM_HOME")
            && !explicit.is_empty()
        {
            return Ok(LpmRoot {
                home: PathBuf::from(explicit),
            });
        }

        let home = dirs::home_dir().ok_or_else(|| {
            LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine home directory (neither $LPM_HOME nor $HOME / $USERPROFILE is set)",
            ))
        })?;

        Ok(LpmRoot {
            home: home.join(".lpm"),
        })
    }

    /// Build an `LpmRoot` pointing at an explicit directory. For tests and
    /// internal migration helpers only.
    pub fn from_dir(home: impl Into<PathBuf>) -> Self {
        LpmRoot { home: home.into() }
    }

    // ─── Core accessors ─────────────────────────────────────────────

    pub fn root(&self) -> &Path {
        &self.home
    }

    // ─── Store ──────────────────────────────────────────────────────

    pub fn store_root(&self) -> PathBuf {
        self.home.join("store")
    }

    /// Legacy v1 store root retained for explicit rollback, migration,
    /// verification, and cleanup. Do not remove this accessor while direct
    /// upgrades from a v1-writing release remain supported.
    pub fn store_v1(&self) -> PathBuf {
        self.store_root().join("v1")
    }

    /// Path to the store's reader/writer lock file.
    ///
    /// `lpm install` and other store-reading commands acquire it as
    /// shared (multiple readers OK); `lpm cache prune --apply` and
    /// `lpm store clean` acquire it as exclusive (waits for in-flight
    /// readers, then blocks new ones until done).
    ///
    /// On-disk path is `~/.lpm/store/.gc.lock` for backwards
    /// compatibility — pre-rename in-flight processes still see the
    /// same file. Renamed from `store_gc_lock` because the lock now
    /// serializes more than gc against itself.
    pub fn store_lock(&self) -> PathBuf {
        self.store_root().join(".gc.lock")
    }

    // ─── Cache ──────────────────────────────────────────────────────

    pub fn cache_root(&self) -> PathBuf {
        self.home.join("cache")
    }

    pub fn cache_metadata(&self) -> PathBuf {
        self.cache_root().join("metadata")
    }

    /// Sigstore attestation snapshots captured per `@name@version` during
    /// install-time provenance-drift checks. Nested under `cache/metadata`
    /// deliberately so the existing `lpm cache clean metadata` sweep already
    /// invalidates it — no new cache category, no new command surface.
    pub fn cache_metadata_attestations(&self) -> PathBuf {
        self.cache_metadata().join("attestations")
    }

    pub fn cache_tasks(&self) -> PathBuf {
        self.cache_root().join("tasks")
    }

    pub fn cache_dlx(&self) -> PathBuf {
        self.cache_root().join("dlx")
    }

    pub fn cache_mcp(&self) -> PathBuf {
        self.cache_root().join("mcp")
    }

    pub fn cache_mcp_lock(&self) -> PathBuf {
        self.cache_root().join(".mcp.lock")
    }

    pub fn cache_clean_lock(&self) -> PathBuf {
        self.cache_root().join(".clean.lock")
    }

    /// Legacy dlx cache location. Used only by the one-shot migration; do not
    /// read or write through this path in new code.
    pub fn legacy_dlx_cache(&self) -> PathBuf {
        self.home.join("dlx-cache")
    }

    // ─── Bin (PATH-exposed shims) ──────────────────────────────────

    pub fn bin_dir(&self) -> PathBuf {
        self.home.join("bin")
    }

    // ─── Plugins (versioned per-name machine-global binaries) ───────

    /// Root of the plugin tree: `~/.lpm/plugins/`.
    /// Plugins are stored as `<plugins_root>/<name>/<version>/<binary>`.
    pub fn plugins_root(&self) -> PathBuf {
        self.home.join("plugins")
    }

    /// Root of the managed-engine tree: `~/.lpm/engines/`.
    /// Engines are stored as `<engines_root>/<name>/<version>/<platform>/...`.
    pub fn engines_root(&self) -> PathBuf {
        self.home.join("engines")
    }

    // ─── Runner: port allocation state ─────────────────────────────

    /// Machine-global port-allocation state at `~/.lpm/ports.toml`.
    /// Consumed by `lpm-runner` to coordinate dev-server ports across
    /// concurrent project invocations.
    pub fn ports_toml(&self) -> PathBuf {
        self.home.join("ports.toml")
    }

    /// Cross-process lock covering dev-service port selection and persistence.
    pub fn ports_lock(&self) -> PathBuf {
        self.home.join(".ports.lock")
    }

    /// Active `lpm dev` endpoint records used by standalone tunnel discovery.
    pub fn dev_sessions_dir(&self) -> PathBuf {
        self.home.join("dev-sessions")
    }

    /// Machine-global local proxy daemon state at `~/.lpm/proxy.json`.
    pub fn proxy_state(&self) -> PathBuf {
        self.home.join("proxy.json")
    }

    /// Local proxy control socket at `~/.lpm/proxy.sock` on Unix platforms.
    /// Windows control uses an owner-restricted named pipe derived by
    /// `lpm-proxy` from the LPM root.
    pub fn proxy_socket(&self) -> PathBuf {
        self.home.join("proxy.sock")
    }

    // ─── Global install tree ────────────────────────────────────────

    pub fn global_root(&self) -> PathBuf {
        self.home.join("global")
    }

    pub fn global_manifest(&self) -> PathBuf {
        self.global_root().join("manifest.toml")
    }

    pub fn global_installs(&self) -> PathBuf {
        self.global_root().join("installs")
    }

    pub fn global_build_state(&self) -> PathBuf {
        self.global_root().join("build-state.json")
    }

    pub fn global_trusted_deps(&self) -> PathBuf {
        self.global_root().join("trusted-dependencies.json")
    }

    pub fn global_wal(&self) -> PathBuf {
        self.global_root().join("wal.jsonl")
    }

    pub fn global_tx_lock(&self) -> PathBuf {
        self.global_root().join(".tx.lock")
    }

    pub fn global_tx_lock_pid(&self) -> PathBuf {
        self.global_root().join(".tx.lock.pid")
    }

    /// The install root for a specific `(name, version)` pair, under
    /// `global/installs/`. Name is sanitized: `@scope/pkg` becomes
    /// `@scope+pkg`, matching existing `lpm-store` conventions.
    ///
    /// M50: also normalises `\` to `+` on every platform. Pre-fix
    /// Windows treated `\` as a path separator, so a registry- or
    /// spec-supplied name like `..\\..\\target` would land
    /// `~/.lpm/global/installs/..\\..\\target@1.0.0/`, which the OS
    /// would interpret as `~/.lpm/global/target@1.0.0/` after parent
    /// traversal — outside the intended directory. Sanitising the
    /// backslash on all platforms keeps Unix and Windows behaviour
    /// in lockstep and removes the platform-specific escape.
    /// Null bytes and traversal segments are also collapsed; the
    /// caller is expected to have validated the name via
    /// `PackageName`, but this is the last line of defence for the
    /// pre-tombstone create/write/rollback path.
    pub fn install_root_for(&self, name: &str, version: &str) -> PathBuf {
        let safe_name = name
            .replace('\0', "")
            .replace("..", "_")
            .replace(['/', '\\'], "+");
        self.global_installs()
            .join(format!("{safe_name}@{version}"))
    }

    // ─── Known-projects registry ─────────────────────────────────────

    /// Machine-global registry of project directories that have ever
    /// completed an `lpm install`. Lives at
    /// `~/.lpm/known-projects.json`. Used by
    /// [`lpm cache prune`](../../lpm-cli/src/commands/cache.rs) as the
    /// root set when computing v2-store orphan reachability — every
    /// project here contributes its `node_modules/<dep>` symlinks
    /// to the "graph keys still in use" set; entries not reachable
    /// from any registered project are pruneable.
    ///
    /// Schema is owned by [`lpm_common::known_projects`]; see that
    /// module for the on-disk JSON shape, atomic-rewrite contract,
    /// and silent-drop policy for moved/deleted projects.
    pub fn known_projects(&self) -> PathBuf {
        self.home.join("known-projects.json")
    }

    // ─── Onboarding / notice markers ────────────────────────────────

    /// Sentinel file created after the first successful `install -g` on a
    /// host, used to suppress the PATH-onboarding banner on subsequent runs.
    pub fn path_hint_marker(&self) -> PathBuf {
        self.home.join(".path-hint-shown")
    }

    /// Sentinel file created after the one-time "cache clean semantics
    /// changed" banner fires, used to suppress it on subsequent runs.
    pub fn cache_clean_notice_marker(&self) -> PathBuf {
        self.home.join(".cache-clean-notice-shown")
    }

    /// Sentinel file created after the one-time network-filesystem warning
    /// fires, used to suppress it on subsequent runs.
    pub fn network_fs_notice_marker(&self) -> PathBuf {
        self.home.join(".network-fs-notice-shown")
    }
}

// ─── Advisory-lock helpers ────────────────────────────────────────────
//
// Writer-preference reader/writer protocol on top of three `fd-lock`
// flock-style files:
//
// - **data lock** (`<lock_path>`) — the actual access lock. Held shared
//   by readers in the body, held exclusive by writers in the body.
// - **writer-intent gate** (`<lock_path>.writer-intent`) — derived
//   automatically from the data lock path. Used to block new reader
//   admissions while a writer owns the gate.
// - **writer-queue baton** (`<lock_path>.writer-queue`) — derived
//   automatically. Held SHARED by every queued writer (including the
//   one currently in the body). Readers probe it with a non-blocking
//   EXCLUSIVE try; if the probe `WouldBlock`s, at least one writer is
//   queued and the reader backs off. Closes the multi-writer
//   starvation hole the gate alone leaves open: between W1 releasing
//   the gate and W2 polling for it, the kernel could otherwise let
//   queued readers grab gate-shared first and leapfrog W2.
//
// Reader flow:
//   1. Non-blocking probe of `writer-queue` exclusive. WouldBlock →
//      a writer is queued; back off. (Probe is microseconds; reader
//      releases queue immediately.)
//   2. Acquire `writer-intent` shared (queue is now empty so this is
//      uncontended in the steady state).
//   3. Acquire `data` shared.
//   4. Drop gate.
//   5. Body. Drop data on exit.
//
// Writer flow:
//   1. Acquire `writer-queue` shared. Multiple writers may queue
//      simultaneously; each one signals "I'm queued" to readers.
//   2. Acquire `writer-intent` exclusive. Blocks new readers from
//      passing the gate; existing in-body readers drain.
//   3. Acquire `data` exclusive. Waits for in-body readers to release.
//   4. Body.
//   5. Release in reverse order: data → gate → queue.
//
// Backwards-compatible with pre-turnstile processes: they only touch
// the data lock and don't observe the gate or queue. The protocol
// degrades between mixed-version processes, but in-flight pre-fix
// processes are bounded, so this is acceptable.

/// How long to wait under contention before emitting the
/// "waiting for…" hint message. Below this, brief contention stays
/// silent.
const LOCK_WAIT_HINT_AFTER: std::time::Duration = std::time::Duration::from_secs(1);
/// Polling interval while waiting for a contended lock. 100 ms gives
/// near-instant wake-up after release at negligible CPU cost.
const LOCK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
const TEST_LOCK_CONTENTION_MARKER_ENV: &str = "LPM_TEST_LOCK_CONTENTION_MARKER";

type LockWaitCallback = Box<dyn FnOnce() + Send>;

/// Derive the writer-intent gate path from the data lock path.
/// `~/.lpm/store/.gc.lock` → `~/.lpm/store/.gc.lock.writer-intent`.
fn writer_intent_path_for(data_path: &Path) -> PathBuf {
    derived_lock_path(data_path, "writer-intent")
}

/// Derive the writer-queue baton path from the data lock path.
/// `~/.lpm/store/.gc.lock` → `~/.lpm/store/.gc.lock.writer-queue`.
fn writer_queue_path_for(data_path: &Path) -> PathBuf {
    derived_lock_path(data_path, "writer-queue")
}

fn derived_lock_path(data_path: &Path, suffix: &str) -> PathBuf {
    let mut p = data_path.to_path_buf();
    let new_name = format!(
        "{}.{suffix}",
        p.file_name().unwrap_or_default().to_string_lossy()
    );
    p.set_file_name(new_name);
    p
}

/// Default "waiting for…" message used by every wrapper that doesn't
/// pass its own. Single short line on stderr — enough to tell a user
/// "you're not stuck, another LPM process is in the way" without
/// claiming a PID we can't actually look up via `fd-lock`.
fn default_wait_hint() {
    eprintln!("{}", format_default_wait_hint());
}

fn format_default_wait_hint() -> String {
    format!(
        "{} Waiting for another lpm operation to finish...",
        "›".blue()
    )
}

/// RAII handle for a held shared (multi-reader) lock. Drop releases.
///
/// We intentionally hold the `fd-lock` `RwLock` rather than its guard
/// — calling `mem::forget` on the guard skips its `flock(LOCK_UN)`
/// drop, leaving the OS-level lock held by the underlying file
/// descriptor. The lock then releases when this handle drops and the
/// file is closed. This shape lets us return ownership of the held
/// lock without bumping into self-referential-struct lifetime issues.
///
/// Readers only retain the data lock — the writer-intent gate is
/// released once they've successfully acquired data-shared, so new
/// writers can immediately raise their gate and queue.
pub struct SharedLockHandle {
    _data: fd_lock::RwLock<std::fs::File>,
}

/// RAII handle for a single-file shared advisory lock.
pub struct SingleFileSharedLockHandle {
    _data: fd_lock::RwLock<std::fs::File>,
}

/// RAII handle for a held exclusive (single-writer) lock. Holds the
/// data lock exclusive, the writer-intent gate exclusive, and the
/// writer-queue baton shared until drop. Field order matters: drop
/// runs `_data → _writer_intent → _writer_queue`, so the access lock
/// releases first, then the new-reader gate is lowered, then the
/// "writer is queued" signal clears. That ordering keeps the writer's
/// successor (if any) from being preempted by readers between
/// release-of-intent and release-of-queue.
pub struct ExclusiveLockHandle {
    _data: fd_lock::RwLock<std::fs::File>,
    _writer_intent: fd_lock::RwLock<std::fs::File>,
    _writer_queue: fd_lock::RwLock<std::fs::File>,
}

/// RAII handle for a single-file exclusive advisory lock.
pub struct SingleFileExclusiveLockHandle {
    _data: fd_lock::RwLock<std::fs::File>,
}

fn open_lock_file(lock_path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
}

/// Acquire a shared lock with a delayed wait-hint callback that fires
/// **at most once** per acquisition. Polls with a 100 ms interval; the
/// hint fires the first time `LOCK_WAIT_HINT_AFTER` elapses. Tests
/// pass a counter-incrementing closure to verify "fires once, not on
/// every poll."
/// What lock mode a poll iteration is trying to acquire.
#[derive(Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

/// Try to acquire `rw` once in the requested mode. On success the
/// guard is `mem::forget`'d so the OS-level lock survives — caller
/// retains the lock by holding `rw` itself.
fn try_acquire(rw: &mut fd_lock::RwLock<std::fs::File>, mode: LockMode) -> Result<bool, LpmError> {
    let attempt = match mode {
        LockMode::Shared => rw.try_read().map(|g| {
            std::mem::forget(g);
        }),
        LockMode::Exclusive => rw.try_write().map(|g| {
            std::mem::forget(g);
        }),
    };
    match attempt {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(LpmError::Io(e)),
    }
}

/// Poll `rw` to acquire `mode`, calling `on_first_wait` exactly once
/// the first time `LOCK_WAIT_HINT_AFTER` of contention has elapsed.
/// Returns when the acquisition succeeds.
fn poll_until_acquired(
    rw: &mut fd_lock::RwLock<std::fs::File>,
    mode: LockMode,
    mut on_first_wait: Option<LockWaitCallback>,
    mut on_first_contention: Option<&mut Option<LockWaitCallback>>,
) -> Result<(), LpmError> {
    let start = std::time::Instant::now();
    loop {
        if try_acquire(rw, mode)? {
            return Ok(());
        }
        if let Some(callback) = on_first_contention.as_deref_mut().and_then(Option::take) {
            callback();
        }
        if on_first_wait.is_some()
            && start.elapsed() >= LOCK_WAIT_HINT_AFTER
            && let Some(cb) = on_first_wait.take()
        {
            cb();
        }
        std::thread::sleep(LOCK_POLL_INTERVAL);
    }
}

fn test_lock_contention_callback(data_path: &Path) -> Option<LockWaitCallback> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let marker_path = std::env::var_os(TEST_LOCK_CONTENTION_MARKER_ENV).map(PathBuf::from)?;
    let lock_path = data_path.to_string_lossy().into_owned();
    Some(Box::new(move || {
        if let Some(parent) = marker_path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            eprintln!(
                "failed to create lock contention marker directory {}: {error}",
                parent.display()
            );
            return;
        }
        if let Err(error) = crate::atomic_write::write_file_atomic(&marker_path, lock_path) {
            eprintln!(
                "failed to write lock contention marker {}: {error}",
                marker_path.display()
            );
        }
    }))
}

/// Probe `rw` non-blocking-exclusive — used by readers to test whether
/// any writer currently holds the queue shared. Returns `Ok(true)` if
/// the probe succeeded (queue is empty; safe to proceed) and the lock
/// has already been released; `Ok(false)` if the probe blocked (a
/// writer is queued and we should back off); `Err` for any other I/O
/// error.
fn probe_queue_empty(rw: &mut fd_lock::RwLock<std::fs::File>) -> Result<bool, LpmError> {
    match rw.try_write() {
        Ok(g) => {
            // Drop the guard immediately — we just used it as a probe.
            // The exclusive grant releases via the guard's normal
            // `flock(LOCK_UN)` drop here; we are NOT keeping the lock.
            drop(g);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(LpmError::Io(e)),
    }
}

/// Acquire a shared lock under the writer-preference turnstile.
///
/// 1. Probe the writer-queue baton. If any writer is queued (probe
///    `WouldBlock`s), back off and retry — this is the multi-writer
///    starvation defense. Hint fires here on prolonged contention.
/// 2. Acquire `gate` shared. Uncontended in the steady state because
///    no writer holds gate exclusive when no writer is queued.
/// 3. Acquire `data` shared.
/// 4. Drop the gate (kept shared only as long as needed to take data).
///
/// Only the data lock is returned in the handle.
fn acquire_shared_with_hint(
    data_path: &Path,
    on_first_wait: impl FnOnce() + Send + 'static,
) -> Result<SharedLockHandle, LpmError> {
    let intent_path = writer_intent_path_for(data_path);
    let queue_path = writer_queue_path_for(data_path);

    let mut on_first_wait = Some(Box::new(on_first_wait) as Box<dyn FnOnce() + Send>);
    let start = std::time::Instant::now();

    // poll the writer-queue baton until no writer is queued.
    // Re-open the file each iteration — the probe transitions through
    // a brief exclusive grant + immediate release; reusing the same
    // RwLock across iterations would require dropping the prior probe
    // anyway, so opening fresh is simpler.
    loop {
        let queue_file = open_lock_file(&queue_path)?;
        let mut queue_rw = fd_lock::RwLock::new(queue_file);
        if probe_queue_empty(&mut queue_rw)? {
            break;
        }
        // queue_rw drops here, closing the fd — no carry between iterations.
        if on_first_wait.is_some()
            && start.elapsed() >= LOCK_WAIT_HINT_AFTER
            && let Some(cb) = on_first_wait.take()
        {
            cb();
        }
        std::thread::sleep(LOCK_POLL_INTERVAL);
    }

    // acquire gate-shared. Uncontended in the steady state.
    let intent_file = open_lock_file(&intent_path)?;
    let mut intent_rw = fd_lock::RwLock::new(intent_file);
    poll_until_acquired(&mut intent_rw, LockMode::Shared, on_first_wait, None)?;

    // acquire data-shared.
    let data_file = open_lock_file(data_path)?;
    let mut data_rw = fd_lock::RwLock::new(data_file);
    poll_until_acquired(&mut data_rw, LockMode::Shared, None, None)?;

    // Drop gate so new writers can raise it immediately.
    drop(intent_rw);
    Ok(SharedLockHandle { _data: data_rw })
}

/// Acquire an exclusive lock under the writer-preference turnstile.
///
/// 1. Acquire `writer-queue` shared. Multiple writers may queue
///    concurrently; their combined shared hold makes readers'
///    queue-exclusive probe `WouldBlock`. This is the multi-writer
///    starvation defense.
/// 2. Acquire `gate` exclusive. Blocks new readers at the gate;
///    existing in-body readers drain naturally.
/// 3. Acquire `data` exclusive. Waits for in-body readers to release.
/// 4. Hold all three for the body. Drop order on exit: data → intent →
///    queue, so the access lock releases first, then new readers are
///    re-admitted only after the next writer (if any) has had a chance
///    to take the queue.
fn acquire_exclusive_with_hint(
    data_path: &Path,
    on_first_wait: impl FnOnce() + Send + 'static,
) -> Result<ExclusiveLockHandle, LpmError> {
    let intent_path = writer_intent_path_for(data_path);
    let queue_path = writer_queue_path_for(data_path);
    let mut on_first_contention = test_lock_contention_callback(data_path);

    // take queue-shared. Multiple writers can each hold this
    // shared simultaneously — that's the point: every queued writer
    // contributes to the "writer is queued" signal readers see.
    let queue_file = open_lock_file(&queue_path)?;
    let mut queue_rw = fd_lock::RwLock::new(queue_file);
    poll_until_acquired(
        &mut queue_rw,
        LockMode::Shared,
        Some(Box::new(on_first_wait)),
        Some(&mut on_first_contention),
    )?;

    // gate exclusive. Blocks new readers from passing the
    // gate. Existing in-body readers don't hold the gate so they
    // don't compete here.
    let intent_file = open_lock_file(&intent_path)?;
    let mut intent_rw = fd_lock::RwLock::new(intent_file);
    poll_until_acquired(
        &mut intent_rw,
        LockMode::Exclusive,
        None,
        Some(&mut on_first_contention),
    )?;

    // data exclusive. Wait for in-body readers to release.
    let data_file = open_lock_file(data_path)?;
    let mut data_rw = fd_lock::RwLock::new(data_file);
    poll_until_acquired(
        &mut data_rw,
        LockMode::Exclusive,
        None,
        Some(&mut on_first_contention),
    )?;

    Ok(ExclusiveLockHandle {
        _data: data_rw,
        _writer_intent: intent_rw,
        _writer_queue: queue_rw,
    })
}

/// Run `body` under a **shared** `fd-lock` advisory lock on
/// `lock_path`. Multiple shared holders may run concurrently;
/// exclusive acquirers block until every shared holder releases.
///
/// The lock file is created if missing (including its parent
/// directory). The lock releases when the internal handle is dropped,
/// so even a panic inside `body` frees it. If the lock is held
/// exclusively by another process, this call blocks until acquired
/// and emits a single "waiting for another lpm store operation to
/// finish…" line on stderr after one second of contention (no PID
/// claim — `fd-lock` doesn't expose lock-owner introspection).
///
/// Used by store-reading commands (`lpm install`, `lpm patch`,
/// `lpm rebuild`, `lpm approve-scripts`, `lpm inventory`,
/// `lpm store path`) so they don't race with `lpm cache prune --apply` /
/// `lpm store clean` mid-read.
pub fn with_shared_lock<P, F, R>(lock_path: P, body: F) -> Result<R, LpmError>
where
    P: AsRef<Path>,
    F: FnOnce() -> Result<R, LpmError>,
{
    let _h = acquire_shared_with_hint(lock_path.as_ref(), default_wait_hint)?;
    body()
}

/// Async variant of [`with_shared_lock`]. The lock acquisition runs on
/// a `tokio::task::spawn_blocking` worker so a contended lock doesn't
/// block the tokio reactor. The acquired handle is held across `body`'s
/// `.await` points and released when the future returns.
///
/// `body` is taken as a future directly (typically an `async {}` block
/// at the call site) — that side-steps the closure-returning-future
/// lifetime puzzle when the body captures references from the caller's
/// stack. The future is constructed before the call but only polled
/// after the lock is acquired.
///
/// This is the entrypoint the install pipeline uses — `commands::install::run_with_options`
/// is async and touches the store across multiple await boundaries
/// (offline gate, fetch loop, link phase).
pub async fn with_shared_lock_async<R>(
    lock_path: PathBuf,
    body: impl std::future::Future<Output = Result<R, LpmError>>,
) -> Result<R, LpmError> {
    let _h = tokio::task::spawn_blocking(move || -> Result<SharedLockHandle, LpmError> {
        acquire_shared_with_hint(&lock_path, default_wait_hint)
    })
    .await
    .map_err(|e| LpmError::Io(std::io::Error::other(format!("lock task join: {e}"))))??;
    body.await
}

/// Run `body` under an **exclusive** `fd-lock` advisory lock on
/// `lock_path`. Blocks until every shared and exclusive holder
/// releases.
///
/// The lock file is created if missing (including its parent
/// directory). The lock releases when the internal handle is dropped,
/// so even a panic inside `body` frees it. This is the canonical
/// primitive for serializing destructive machine-global operations —
/// `lpm cache clean`, `lpm store clean`, `lpm cache prune --apply`, and the
/// `.tx.lock`-guarded install-commit section.
///
/// On contention, emits the same one-shot "waiting for…" hint as
/// [`with_shared_lock`] after one second.
///
/// **Lock scope is per-path.** Callers that want the *same*
/// serialization domain must pass the *same* path. Established roots:
///
/// - [`LpmRoot::cache_clean_lock`] — `lpm cache clean`
/// - [`LpmRoot::store_lock`]       — store readers (shared) + `lpm cache prune --apply` / `lpm store clean` (exclusive)
/// - `LpmRoot::global_tx_lock`     — install/uninstall tx
///
/// **Advisory semantics.** Processes that don't participate in the
/// locking protocol are not blocked — this defends against concurrent
/// `lpm` invocations, not against external tools that reach directly
/// into `~/.lpm/`.
pub fn with_exclusive_lock<P, F, R>(lock_path: P, body: F) -> Result<R, LpmError>
where
    P: AsRef<Path>,
    F: FnOnce() -> Result<R, LpmError>,
{
    let _h = acquire_exclusive_with_hint(lock_path.as_ref(), default_wait_hint)?;
    body()
}

/// Acquire and return an exclusive advisory lock handle.
///
/// The caller controls the critical-section lifetime by retaining the returned
/// handle. This is useful when existing control flow contains early returns or
/// loop `continue` paths that would make a closure-scoped lock cumbersome.
pub fn acquire_exclusive_lock(
    lock_path: impl AsRef<Path>,
) -> Result<ExclusiveLockHandle, LpmError> {
    acquire_exclusive_with_hint(lock_path.as_ref(), default_wait_hint)
}

/// Acquire a shared advisory lock that retains one file descriptor.
///
/// Use this with [`acquire_single_file_exclusive_lock`] for high-cardinality,
/// independent lock domains whose critical sections are bounded. Unlike the
/// writer-preferred store-wide locks, this compact pair does not allocate
/// separate queue and intent descriptors per key.
pub fn acquire_single_file_shared_lock(
    lock_path: impl AsRef<Path>,
) -> Result<SingleFileSharedLockHandle, LpmError> {
    let file = open_lock_file(lock_path.as_ref())?;
    let mut data = fd_lock::RwLock::new(file);
    poll_until_acquired(
        &mut data,
        LockMode::Shared,
        Some(Box::new(default_wait_hint)),
        None,
    )?;
    Ok(SingleFileSharedLockHandle { _data: data })
}

/// Acquire an exclusive advisory lock that retains one file descriptor.
///
/// This is the exclusive half of [`acquire_single_file_shared_lock`].
pub fn acquire_single_file_exclusive_lock(
    lock_path: impl AsRef<Path>,
) -> Result<SingleFileExclusiveLockHandle, LpmError> {
    let file = open_lock_file(lock_path.as_ref())?;
    acquire_single_file_exclusive_lock_from_file(file)
}

pub(crate) fn acquire_single_file_exclusive_lock_from_file(
    file: std::fs::File,
) -> Result<SingleFileExclusiveLockHandle, LpmError> {
    let mut data = fd_lock::RwLock::new(file);
    poll_until_acquired(
        &mut data,
        LockMode::Exclusive,
        Some(Box::new(default_wait_hint)),
        None,
    )?;
    Ok(SingleFileExclusiveLockHandle { _data: data })
}

/// Try to acquire an exclusive advisory lock without waiting.
///
/// Returns `Ok(Some(handle))` when all writer-preference lock components
/// were acquired, or `Ok(None)` when a reader or writer already owns the
/// lock domain. Partially acquired components are released before returning
/// `None`.
pub fn try_acquire_exclusive_lock(
    lock_path: impl AsRef<Path>,
) -> Result<Option<ExclusiveLockHandle>, LpmError> {
    let data_path = lock_path.as_ref();
    let intent_path = writer_intent_path_for(data_path);
    let queue_path = writer_queue_path_for(data_path);

    let queue_file = open_lock_file(&queue_path)?;
    let mut queue_rw = fd_lock::RwLock::new(queue_file);
    if !try_acquire(&mut queue_rw, LockMode::Shared)? {
        return Ok(None);
    }

    let intent_file = open_lock_file(&intent_path)?;
    let mut intent_rw = fd_lock::RwLock::new(intent_file);
    if !try_acquire(&mut intent_rw, LockMode::Exclusive)? {
        return Ok(None);
    }

    let data_file = open_lock_file(data_path)?;
    let mut data_rw = fd_lock::RwLock::new(data_file);
    if !try_acquire(&mut data_rw, LockMode::Exclusive)? {
        return Ok(None);
    }

    Ok(Some(ExclusiveLockHandle {
        _data: data_rw,
        _writer_intent: intent_rw,
        _writer_queue: queue_rw,
    }))
}

/// Async variant of [`with_exclusive_lock`]. The lock acquisition runs on
/// a `tokio::task::spawn_blocking` worker so a contended lock doesn't
/// block the tokio reactor. The acquired handle is held across `body`'s
/// `.await` points and released when the future returns.
///
/// Mirrors [`with_shared_lock_async`]'s shape — `body` is a future taken
/// directly so callers can pass an `async {}` block at the call site,
/// side-stepping the closure-returning-future lifetime puzzle when the
/// body captures references from the caller's stack. The future is
/// constructed before the call but only polled after the lock is
/// acquired.
///
/// Used by lpm-plugin's install path so a contended plugin install
/// doesn't block other unrelated tokio work while one process waits to
/// download a binary.
pub async fn with_exclusive_lock_async<R>(
    lock_path: PathBuf,
    body: impl std::future::Future<Output = Result<R, LpmError>>,
) -> Result<R, LpmError> {
    let _h = tokio::task::spawn_blocking(move || -> Result<ExclusiveLockHandle, LpmError> {
        acquire_exclusive_with_hint(&lock_path, default_wait_hint)
    })
    .await
    .map_err(|e| LpmError::Io(std::io::Error::other(format!("lock task join: {e}"))))??;
    body.await
}

/// Non-blocking variant of [`with_exclusive_lock`]. Returns `Ok(Some(R))`
/// if the lock was acquired and `body` ran to completion; `Ok(None)`
/// if the lock was already held by another process (caller should
/// silently continue — the holder will run its own commit). Any
/// non-WouldBlock I/O error propagates as `Err`.
///
/// Used by `lpm_global::recover()` to skip recovery when another `lpm`
/// process is already inside a global install transaction. Recovery is
/// idempotent and safe to defer to the next invocation.
pub fn try_with_exclusive_lock<P, F, R>(lock_path: P, body: F) -> Result<Option<R>, LpmError>
where
    P: AsRef<Path>,
    F: FnOnce() -> Result<R, LpmError>,
{
    let lock_path = lock_path.as_ref();
    let file = open_lock_file(lock_path)?;
    let mut lock = fd_lock::RwLock::new(file);
    match lock.try_write() {
        Ok(_guard) => body().map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(LpmError::Io(e)),
    }
}

// ─── Project install lock ─────────────────────────────────────────────

/// Path to the per-project `lpm install` exclusive lock at
/// `<project_dir>/.lpm/.install.lock`.
///
/// Acquired exclusively (via [`with_exclusive_lock_async`]) by the
/// `lpm install`, `lpm install <pkg>`, `lpm install --filter`, and
/// `lpm add` entry points so two concurrent invocations on the same
/// project serialize through the manifest snapshot → install →
/// lockfile commit window. Without this lock, both processes would
/// snapshot the same pre-edit `package.json`, both stage their own
/// dep on top, and the second-to-commit silently overwrites the
/// first's edits.
///
/// Lock scope is per-project: unrelated installs in different
/// projects do not contend. Within a single project, the lock holds
/// from `ManifestTransaction::snapshot_install_state` through
/// `tx.commit()`, covering `package.json` + `lpm.lock` + `lpm.lockb`
/// + `.lpm/install-hash` + `node_modules/` mutations.
///
/// **Advisory semantics.** External tools (manual edits to
/// `package.json`, `rm -rf node_modules`) are not blocked. Defends
/// only against concurrent `lpm` invocations that participate in
/// the locking protocol.
///
/// **Accepted-posture trade-off (L31):** under heavy concurrent
/// activity (e.g., the user re-running `lpm install` in two
/// terminals AND an IDE auto-formatter rewriting `package.json` in
/// parallel), `ManifestTransaction::rollback` can clobber the
/// editor's concurrent edits when restoring the snapshot. Trading
/// reliable rollback semantics for cross-process notify/lock
/// integration with IDEs was rejected as out of scope for the
/// install layer; the documented contract is "do not edit
/// `package.json` while an `lpm install` is in flight."
///
/// **The lock file's parent (`<project_dir>/.lpm/`) is created on
/// demand by [`open_lock_file`]** — callers do not need to mkdir
/// first. The same `.lpm/` directory holds `install-hash` and is
/// the canonical project-local LPM state directory.
pub fn project_install_lock(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(".install.lock")
}

// ─── Windows long-path helper ─────────────────────────────────────────

/// Return a path safe for filesystem APIs that would otherwise hit the
/// Win32 MAX_PATH (260-char) ceiling.
///
/// On Windows, absolute paths longer than 259 characters are truncated by
/// the legacy API unless they carry the `\\?\` extended-length prefix.
/// This helper is a no-op on other platforms and on paths that are already
/// prefixed, relative, or short enough to be safe.
///
/// Call this for every filesystem operation under `~/.lpm/global/installs/`
/// — the combination of `$LPM_HOME` + scope + `@ver` + nested `node_modules`
/// chains routinely pushes paths past the ceiling.
pub fn as_extended_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        // Skip if already prefixed with \\?\ or \\.\ (device namespace)
        if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
            return path.to_path_buf();
        }
        // Skip relative paths — the prefix is only meaningful on absolute ones
        if !path.is_absolute() {
            return path.to_path_buf();
        }
        // UNC paths use \\?\UNC\server\share form
        if let Some(stripped) = s.strip_prefix(r"\\") {
            return PathBuf::from(format!(r"\\?\UNC\{stripped}"));
        }
        PathBuf::from(format!(r"\\?\{s}"))
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

/// Absolute-path budget for a global install root before nested
/// `node_modules/.bin/<cmd>.cmd` traversal would push us over the legacy
/// Win32 MAX_PATH ceiling (260). Allows 13 chars of headroom for the deepest
/// expected suffix.
pub const GLOBAL_INSTALL_PATH_BUDGET: usize = 247;

/// Reject install-root paths that would overflow Windows' legacy MAX_PATH
/// once normal nested `node_modules/.bin/...` paths are appended.
///
/// On non-Windows hosts this is a no-op — POSIX has no equivalent ceiling
/// and the [`as_extended_path`] prefix already handles everything for us
/// on Windows when paths are constructed individually. The pre-check
/// catches the remaining failure mode: the install root *itself* being
/// long enough that legacy fs APIs (or third-party tools that don't honour
/// the extended-length prefix) would truncate. Failing fast with an
/// actionable hint beats failing mid-extraction with cryptic errors.
///
/// `install_root` should be the absolute path of the would-be install root
/// (e.g. `~/.lpm/global/installs/<name>@<ver>/`). Caller is responsible
/// for canonicalising before calling — `Path::canonicalize()` won't work
/// because the directory doesn't exist yet, so callers typically join the
/// canonicalised parent (`~/.lpm/global/installs/`) with the new leaf name.
pub fn check_install_path_budget(install_root: &Path) -> Result<(), LpmError> {
    let len = install_root.to_string_lossy().len();
    if len <= GLOBAL_INSTALL_PATH_BUDGET {
        return Ok(());
    }
    Err(LpmError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "global install root would exceed the {GLOBAL_INSTALL_PATH_BUDGET}-char budget \
             ({len} chars at {}). Set LPM_HOME to a shorter path \
             (e.g. LPM_HOME=/var/lpm or LPM_HOME=C:\\lpm) and retry. \
             Long-path support varies across Windows tooling; this guard \
             prevents cryptic mid-install failures on hosts where the \
             legacy MAX_PATH ceiling still applies.",
            install_root.display(),
        ),
    )))
}

// ─── Network-filesystem detection ─────────────────────────────────────

/// Classification of the filesystem backing a given path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// Local storage — advisory locks are reliable.
    Local,
    /// Known unreliable networked filesystem (NFS / SMB / CIFS / AFP).
    /// Advisory locks are lying-or-incomplete; emit a warning at bootstrap.
    Network,
    /// Unknown (statfs failed, unfamiliar filesystem type). Treat as local
    /// to avoid false-positive warnings for legitimate FUSE mounts, tmpfs
    /// on Linux, APFS snapshots, etc.
    Unknown,
}

#[cfg(target_os = "linux")]
fn classify_linux_filesystem(fs_type: u64) -> FsKind {
    const NFS_SUPER_MAGIC: u64 = 0x6969;
    const SMB_SUPER_MAGIC: u64 = 0x517B;
    const SMB2_MAGIC_NUMBER: u64 = 0xFE53_4D42;
    const CIFS_MAGIC_NUMBER: u64 = 0xFF53_4D42;
    const CODA_SUPER_MAGIC: u64 = 0x7375_7245;

    match fs_type {
        NFS_SUPER_MAGIC | SMB_SUPER_MAGIC | SMB2_MAGIC_NUMBER | CIFS_MAGIC_NUMBER
        | CODA_SUPER_MAGIC => FsKind::Network,
        _ => FsKind::Local,
    }
}

/// Best-effort detection of whether `path` lives on a local filesystem.
///
/// The detection is used only to emit a one-time diagnostic warning when
/// `$LPM_HOME` sits on NFS/SMB. We intentionally default to treating
/// unknown filesystems as local — false positives on obscure-but-reliable
/// mounts (FUSE, tmpfs, loopback) would be more annoying than the rare
/// missed NFS warning.
pub fn is_local_fs(path: &Path) -> FsKind {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/mountinfo parsing would be more robust, but statfs with
        // f_type matching is simpler and good enough for the warning use case.
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return FsKind::Unknown;
        };
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
        if rc != 0 {
            return FsKind::Unknown;
        }
        classify_linux_filesystem(buf.f_type as u64)
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return FsKind::Unknown;
        };
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
        if rc != 0 {
            return FsKind::Unknown;
        }
        // f_fstypename is a null-terminated [c_char; MFSTYPENAMELEN]. Convert
        // to &str for comparison; any non-UTF8 implies an exotic FS we
        // should not try to classify.
        let raw: Vec<u8> = buf
            .f_fstypename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        let Ok(fstype) = std::str::from_utf8(&raw) else {
            return FsKind::Unknown;
        };
        match fstype {
            "nfs" | "smbfs" | "cifs" | "afpfs" | "webdav" => FsKind::Network,
            _ => FsKind::Local,
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

        // `DRIVE_REMOTE` is part of the stable Win32 ABI — value 4 since
        // Windows NT. Inlining the constant avoids pulling in another
        // `windows-sys` feature flag (`Win32_System_WindowsProgramming`,
        // where windows-sys 0.60+ now exposes the symbol) for a single
        // numeric literal that hasn't moved in three decades.
        const DRIVE_REMOTE: u32 = 4;

        // GetDriveTypeW takes a root path like "C:\\". Extract the root
        // component of the input; if we can't, default to Unknown.
        let Some(root) = path.ancestors().last() else {
            return FsKind::Unknown;
        };
        let wide: Vec<u16> = root
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if drive_type == DRIVE_REMOTE {
            FsKind::Network
        } else {
            FsKind::Local
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = path;
        FsKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_filesystem_magic_classifies_nfs_as_network() {
        assert_eq!(classify_linux_filesystem(0x6969), FsKind::Network);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_filesystem_magic_classifies_unknown_type_as_local() {
        assert_eq!(classify_linux_filesystem(0x0102_1994), FsKind::Local);
    }

    #[test]
    fn from_env_respects_lpm_home_override() {
        let tmp = TempDir::new().unwrap();
        // Use set_var under a mutex in a real project; for one-shot tests the
        // env is process-local and we're not racing with other threads that
        // read LPM_HOME.
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let root = LpmRoot::from_env().unwrap();
        assert_eq!(root.root(), tmp.path());
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
    }

    #[test]
    fn from_env_falls_back_to_home_dot_lpm() {
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        let root = LpmRoot::from_env().unwrap();
        assert_eq!(root.root().file_name().unwrap(), ".lpm");
    }

    #[test]
    fn from_dir_injects_explicit_home() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        assert_eq!(root.root(), tmp.path());
    }

    #[test]
    fn accessors_all_compose_under_home() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        for p in [
            root.store_root(),
            root.store_v1(),
            root.store_lock(),
            root.cache_root(),
            root.cache_metadata(),
            root.cache_tasks(),
            root.cache_dlx(),
            root.cache_mcp(),
            root.cache_mcp_lock(),
            root.cache_clean_lock(),
            root.legacy_dlx_cache(),
            root.bin_dir(),
            root.plugins_root(),
            root.ports_toml(),
            root.ports_lock(),
            root.global_root(),
            root.global_manifest(),
            root.global_installs(),
            root.global_build_state(),
            root.global_trusted_deps(),
            root.global_wal(),
            root.global_tx_lock(),
            root.global_tx_lock_pid(),
            root.install_root_for("eslint", "9.24.0"),
            root.install_root_for("@lpm.dev/owner.tool", "1.2.0"),
            root.path_hint_marker(),
            root.cache_clean_notice_marker(),
            root.network_fs_notice_marker(),
        ] {
            assert!(
                p.starts_with(tmp.path()),
                "accessor produced {p:?} outside root"
            );
        }
    }

    #[test]
    fn install_root_for_sanitizes_scoped_names() {
        let root = LpmRoot::from_dir("/tmp/lpm-test");
        let p = root.install_root_for("@lpm.dev/owner.tool", "1.2.0");
        let tail = p.file_name().unwrap().to_string_lossy();
        assert_eq!(tail, "@lpm.dev+owner.tool@1.2.0");
        assert!(!tail.contains('/'));
    }

    /// M50: backslashes are sanitised to `+` on every platform — not
    /// just `/`. Pre-fix, Windows treated `\` as a path separator, so
    /// a registry- or spec-supplied name like `..\\..\\target` would
    /// escape the installs dir. Same posture on Unix (defence in depth
    /// — backslash isn't a separator there but normalising keeps the
    /// behaviour consistent).
    #[test]
    fn install_root_for_neutralises_windows_backslashes() {
        let root = LpmRoot::from_dir("/tmp/lpm-test");
        let p = root.install_root_for("evil\\..\\target", "1.0.0");
        let tail = p.file_name().unwrap().to_string_lossy();
        assert!(!tail.contains('\\'), "backslash must be sanitised: {tail}");
        // The `..` substring collapses to `_` so the directory name
        // can't be re-interpreted as a parent-traversal by the OS.
        assert!(
            !tail.contains(".."),
            "parent-traversal segment must collapse: {tail}"
        );
    }

    /// M50: null bytes in the name are stripped before path
    /// composition. The pre-fix path could pass `\0` into
    /// `PathBuf::join`, where Unix would happily build a path
    /// containing the byte (which downstream POSIX syscalls might
    /// then truncate at).
    #[test]
    fn install_root_for_strips_null_bytes() {
        let root = LpmRoot::from_dir("/tmp/lpm-test");
        let p = root.install_root_for("name\0evil", "1.0.0");
        let tail = p.file_name().unwrap().to_string_lossy();
        assert!(!tail.contains('\0'), "null byte must be stripped: {tail}");
    }

    #[test]
    fn default_wait_hint_uses_slim_phase_shape() {
        let hint = format_default_wait_hint();

        assert!(
            hint.contains('›'),
            "wait hint should use phase glyph: {hint:?}"
        );
        assert!(
            hint.contains("Waiting for another lpm operation to finish..."),
            "wait hint should explain contention: {hint:?}"
        );
    }

    #[test]
    fn as_extended_path_is_noop_on_unix() {
        #[cfg(not(windows))]
        {
            let p = Path::new("/some/long/path");
            assert_eq!(as_extended_path(p), p);
        }
    }

    #[test]
    #[cfg(windows)]
    fn as_extended_path_prefixes_absolute_windows_paths() {
        let p = Path::new(r"C:\Users\test\AppData\Local\.lpm\global\installs\pkg@1.0.0");
        let got = as_extended_path(p);
        assert!(got.to_string_lossy().starts_with(r"\\?\"));
    }

    #[test]
    #[cfg(windows)]
    fn as_extended_path_skips_already_prefixed() {
        let p = Path::new(r"\\?\C:\already\prefixed");
        assert_eq!(as_extended_path(p), p);
    }

    #[test]
    #[cfg(windows)]
    fn as_extended_path_skips_relative() {
        let p = Path::new(r"some\relative\path");
        assert_eq!(as_extended_path(p), p);
    }

    #[test]
    fn with_exclusive_lock_runs_body_and_releases() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("sub").join("test.lock");
        let got = with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(42)).unwrap();
        assert_eq!(got, 42);
        // Parent dir created on demand.
        assert!(lock_path.parent().unwrap().is_dir());
        assert!(lock_path.is_file());
        // Re-acquire: the prior guard must have been released on scope exit.
        let got2 = with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(7)).unwrap();
        assert_eq!(got2, 7);
    }

    #[test]
    fn try_with_exclusive_lock_returns_some_when_uncontended() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");
        let got = try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(99)).unwrap();
        assert_eq!(got, Some(99));
    }

    #[test]
    fn try_with_exclusive_lock_returns_none_when_held_by_other_process() {
        // Simulate "another process holds the lock" by holding it on a
        // background thread for the duration of the try call. Both
        // threads use fd-lock against the same path — same semantics
        // as cross-process contention.
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_for_thread = lock_path.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_for_thread, move || {
                held_tx.send(()).unwrap();
                // Hold the lock until the test signals release.
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        // Wait until the holder confirms it owns the lock.
        held_rx.recv().unwrap();

        let got = try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(())).unwrap();
        assert!(
            got.is_none(),
            "try_with_exclusive_lock must not block when contended"
        );

        release_tx.send(()).unwrap();
        handle.join().unwrap().unwrap();

        // After the holder releases, the next attempt succeeds.
        let got2 = try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(7)).unwrap();
        assert_eq!(got2, Some(7));
    }

    #[test]
    fn with_exclusive_lock_propagates_body_error() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");
        let err = with_exclusive_lock(&lock_path, || {
            Err::<(), _>(LpmError::Io(std::io::Error::other("test error")))
        });
        assert!(err.is_err());
        // Lock must be released even after a body error; a second call succeeds.
        with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(())).unwrap();
    }

    #[test]
    fn try_acquire_exclusive_lock_returns_a_held_raii_handle() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let first = try_acquire_exclusive_lock(&lock_path)
            .unwrap()
            .expect("uncontended lock must be acquired");
        assert!(
            try_acquire_exclusive_lock(&lock_path).unwrap().is_none(),
            "the returned handle must retain the exclusive lock"
        );
        drop(first);
        assert!(
            try_acquire_exclusive_lock(&lock_path).unwrap().is_some(),
            "dropping the handle must release the exclusive lock"
        );
    }

    #[test]
    fn check_install_path_budget_accepts_short_path() {
        let p = PathBuf::from("/tmp/lpm/global/installs/eslint@9.24.0");
        assert!(check_install_path_budget(&p).is_ok());
    }

    #[test]
    fn check_install_path_budget_accepts_path_at_budget_boundary() {
        // Build a path whose total length exactly hits the budget.
        let prefix = "/x/";
        let pad = "a".repeat(GLOBAL_INSTALL_PATH_BUDGET - prefix.len());
        let p = PathBuf::from(format!("{prefix}{pad}"));
        assert_eq!(p.to_string_lossy().len(), GLOBAL_INSTALL_PATH_BUDGET);
        assert!(check_install_path_budget(&p).is_ok());
    }

    #[test]
    fn check_install_path_budget_rejects_overlong_path_with_actionable_hint() {
        let p = PathBuf::from(format!("/{}", "a".repeat(GLOBAL_INSTALL_PATH_BUDGET + 1)));
        let err = check_install_path_budget(&p).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("LPM_HOME"), "missing actionable hint: {msg}");
        assert!(msg.contains(&GLOBAL_INSTALL_PATH_BUDGET.to_string()));
    }

    #[test]
    fn is_local_fs_returns_sane_value_for_tempdir() {
        let tmp = TempDir::new().unwrap();
        // Temp dirs are always local on supported platforms; on everything
        // else we expect Unknown, which we still treat as non-Network.
        let kind = is_local_fs(tmp.path());
        assert_ne!(kind, FsKind::Network, "tempdir classified as Network");
    }

    // ─── Reader/writer lock semantics ─────────────────────────────────

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// Two shared acquires on the same path may overlap.
    #[test]
    fn shared_locks_can_overlap() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_t = lock_path.clone();
        let (acq_tx, acq_rx) = std::sync::mpsc::channel::<()>();
        let (rel_tx, rel_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            with_shared_lock(&lock_path_t, move || {
                acq_tx.send(()).unwrap();
                rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });

        acq_rx.recv().unwrap();

        // While holder still has its shared lock, the second shared
        // acquire should succeed without blocking.
        let start = Instant::now();
        let got = with_shared_lock(&lock_path, || Ok::<_, LpmError>(123)).unwrap();
        assert_eq!(got, 123);
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "second shared acquire should not block",
        );

        rel_tx.send(()).unwrap();
        holder.join().unwrap().unwrap();
    }

    /// Shared lock blocks an exclusive acquire until released.
    #[test]
    fn exclusive_blocks_while_shared_held() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_t = lock_path.clone();
        let (acq_tx, acq_rx) = std::sync::mpsc::channel::<()>();
        let (rel_tx, rel_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            with_shared_lock(&lock_path_t, move || {
                acq_tx.send(()).unwrap();
                rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        acq_rx.recv().unwrap();

        // Exclusive acquire should NOT succeed quickly while the
        // shared lock is held — try the non-blocking variant.
        let attempt = try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(())).unwrap();
        assert!(
            attempt.is_none(),
            "exclusive must be blocked while shared lock is held",
        );

        // Release the shared holder and confirm the exclusive can now
        // acquire.
        rel_tx.send(()).unwrap();
        holder.join().unwrap().unwrap();

        let attempt2 = try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(()));
        assert!(
            attempt2.unwrap().is_some(),
            "exclusive must succeed after shared release",
        );
    }

    /// Exclusive lock blocks subsequent shared acquires until released.
    #[test]
    fn shared_blocks_while_exclusive_held() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_t = lock_path.clone();
        let (acq_tx, acq_rx) = std::sync::mpsc::channel::<()>();
        let (rel_tx, rel_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_t, move || {
                acq_tx.send(()).unwrap();
                rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        acq_rx.recv().unwrap();

        // Background shared acquire should be blocked while we hold
        // exclusive. We start it and confirm it doesn't complete
        // within a short window.
        let lock_path_s = lock_path;
        let shared_done = Arc::new(AtomicUsize::new(0));
        let shared_done_t = shared_done.clone();
        let shared_handle = std::thread::spawn(move || {
            with_shared_lock(&lock_path_s, move || {
                shared_done_t.fetch_add(1, Ordering::SeqCst);
                Ok::<_, LpmError>(())
            })
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            shared_done.load(Ordering::SeqCst),
            0,
            "shared must remain blocked while exclusive is held",
        );

        // Release exclusive and confirm the shared completes.
        rel_tx.send(()).unwrap();
        holder.join().unwrap().unwrap();
        shared_handle.join().unwrap().unwrap();
        assert_eq!(shared_done.load(Ordering::SeqCst), 1);
    }

    /// Wait-hint callback fires AT MOST ONCE per acquisition, not on
    /// every poll.
    #[test]
    fn wait_hint_fires_exactly_once() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        // Hold an exclusive lock so the shared acquire blocks. We'll
        // hold for ~2.5 seconds, well past the 1-second hint deadline,
        // so the polling loop runs many iterations after the hint
        // fires once.
        let lock_path_t = lock_path.clone();
        let (acq_tx, acq_rx) = std::sync::mpsc::channel::<()>();
        let (rel_tx, rel_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_t, move || {
                acq_tx.send(()).unwrap();
                rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        acq_rx.recv().unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_t = counter.clone();

        let lock_path_s = lock_path;
        let waiter = std::thread::spawn(move || -> Result<SharedLockHandle, LpmError> {
            acquire_shared_with_hint(&lock_path_s, move || {
                counter_t.fetch_add(1, Ordering::SeqCst);
            })
        });

        // Wait long enough for the hint to fire (1s) plus several
        // additional poll intervals (~100ms each) where it must NOT
        // fire again.
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "wait hint must fire exactly once across the contended polling window",
        );

        // Release the exclusive lock; waiter completes; counter still 1.
        rel_tx.send(()).unwrap();
        holder.join().unwrap().unwrap();
        let _h = waiter.join().unwrap().unwrap();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "wait hint must not fire on the successful acquire",
        );
    }

    /// Wait hint never fires when contention is brief (under 1 second).
    #[test]
    fn wait_hint_does_not_fire_on_short_contention() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_t = lock_path.clone();
        let (acq_tx, acq_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_t, move || {
                acq_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(300));
                Ok::<_, LpmError>(())
            })
        });
        acq_rx.recv().unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_t = counter.clone();

        let _h = acquire_shared_with_hint(&lock_path, move || {
            counter_t.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();

        holder.join().unwrap().unwrap();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "wait hint must NOT fire when contention resolves under 1s",
        );
    }

    /// Lock is released even if the body panics.
    #[test]
    fn lock_releases_on_panic() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_t = lock_path.clone();
        let panicked = std::thread::spawn(move || {
            let _ = with_shared_lock::<_, _, ()>(&lock_path_t, || {
                panic!("intentional");
            });
        })
        .join();
        assert!(panicked.is_err());

        // Lock must be releasable now.
        let attempt = try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(()));
        assert!(
            attempt.unwrap().is_some(),
            "lock must release on panic so subsequent acquires succeed",
        );
    }

    /// Async helper holds the shared lock across `.await` points.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_lock_async_blocks_exclusive_during_body() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        let lock_path_inner = lock_path.clone();
        let body = async move {
            // Sleep across an await to confirm the lock is held the
            // whole time (not just at acquire).
            tokio::time::sleep(Duration::from_millis(300)).await;
            // The lock_path used by the helper is `lock_path` (cloned
            // into the spawn_blocking closure) — at this point the
            // exclusive try below must observe the lock held.
            let _ = lock_path_inner;
            Ok::<_, LpmError>(())
        };

        let lock_path_for_async = lock_path.clone();
        let async_handle =
            tokio::spawn(async move { with_shared_lock_async(lock_path_for_async, body).await });

        // Give the async task a moment to acquire.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // While the async body is sleeping inside the lock, an
        // exclusive try-acquire from a sync context should fail.
        let lock_path_check = lock_path.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            try_with_exclusive_lock(&lock_path_check, || Ok::<_, LpmError>(()))
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            attempt.is_none(),
            "exclusive must be blocked while async shared lock is held across await",
        );

        async_handle.await.unwrap().unwrap();

        // After the async body completes, exclusive can acquire again.
        let attempt2 = tokio::task::spawn_blocking(move || {
            try_with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(()))
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            attempt2.is_some(),
            "exclusive must succeed after async release"
        );
    }

    /// Async helper holds the exclusive lock across `.await` points so a
    /// second async acquirer waits until the first releases. Mirrors the
    /// shared-async test shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exclusive_lock_async_serializes_two_concurrent_acquires() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        // The two tasks each: acquire → push enter timestamp → sleep across
        // an await → push exit timestamp → release. If serialized, the
        // intervals don't overlap.
        let log = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<(u8, u8)>::new()));

        let task = |id: u8, log: std::sync::Arc<tokio::sync::Mutex<Vec<(u8, u8)>>>| {
            let lock_path = lock_path.clone();
            tokio::spawn(async move {
                let log_inner = log.clone();
                let body = async move {
                    log_inner.lock().await.push((id, 0));
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    log_inner.lock().await.push((id, 1));
                    Ok::<_, LpmError>(())
                };
                with_exclusive_lock_async(lock_path, body).await
            })
        };

        let t1 = task(1, log.clone());
        // Give task 1 a moment to acquire the lock first.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let t2 = task(2, log.clone());

        t1.await.unwrap().unwrap();
        t2.await.unwrap().unwrap();

        let events = log.lock().await.clone();
        assert_eq!(
            events,
            vec![(1, 0), (1, 1), (2, 0), (2, 1)],
            "with_exclusive_lock_async must serialize: task 1 enters, task 1 exits, then task 2 — never interleaved"
        );
    }

    /// Concrete proof of the lpm-plugin contract: when both tasks target
    /// the SAME lock path (mirrors per-(name, version) install lock or
    /// per-name update lock), they serialize. When they target DIFFERENT
    /// lock paths (different plugin versions / different plugin names),
    /// they run in parallel.
    ///
    /// Uses a `Barrier::new(2)` rendezvous inside both bodies — the
    /// barrier only resolves when both tasks are simultaneously inside
    /// their lock, which is mathematically impossible if they had
    /// serialized on the same lock (one would still be waiting on
    /// acquire). Wrapped in `tokio::time::timeout` so a serialization
    /// regression fails loudly within bounded time instead of hanging
    /// the test runner. Replaces an earlier sleep-and-check-counter
    /// approach that was timing-dependent and flaky on loaded runners.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exclusive_lock_async_different_paths_run_in_parallel() {
        let tmp = TempDir::new().unwrap();
        let path_a = tmp.path().join("a.lock");
        let path_b = tmp.path().join("b.lock");

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

        let task = |path: PathBuf, barrier: std::sync::Arc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                let body = async move {
                    // If the other task is held back on a contended
                    // lock, it never reaches its `barrier.wait().await`,
                    // and this `wait()` blocks forever. The outer
                    // timeout catches that and fails the test.
                    barrier.wait().await;
                    Ok::<_, LpmError>(())
                };
                with_exclusive_lock_async(path, body).await
            })
        };

        let t1 = task(path_a, barrier.clone());
        let t2 = task(path_b, barrier);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            t1.await.unwrap().unwrap();
            t2.await.unwrap().unwrap();
        })
        .await;

        assert!(
            result.is_ok(),
            "different lock paths must NOT serialize — both bodies must reach the barrier concurrently. \
             Timeout means they were forced to run sequentially (regression in lock scope)."
        );
    }

    /// Writer preference: once an exclusive acquire is queued behind
    /// in-flight readers, NEW readers must block at the writer-intent
    /// gate until the writer has run. Without the turnstile, a steady
    /// stream of readers would starve the writer indefinitely
    /// (`flock` itself has no SH-vs-EX fairness guarantee).
    ///
    /// This scenario was possible in the pre-turnstile design.
    #[test]
    fn late_reader_blocks_when_writer_queued() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        // Step 1: long-running reader holds shared.
        let lock_path_r1 = lock_path.clone();
        let (r1_acq_tx, r1_acq_rx) = std::sync::mpsc::channel::<()>();
        let (r1_rel_tx, r1_rel_rx) = std::sync::mpsc::channel::<()>();
        let r1 = std::thread::spawn(move || {
            with_shared_lock(&lock_path_r1, move || {
                r1_acq_tx.send(()).unwrap();
                r1_rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        r1_acq_rx.recv().unwrap();

        // Step 2: writer arrives and queues. It will:
        //   - acquire writer-intent exclusive immediately (no one
        //     else holds it),
        //   - then block on data-exclusive while r1 holds data-shared.
        let lock_path_w = lock_path.clone();
        let (w_acq_tx, w_acq_rx) = std::sync::mpsc::channel::<()>();
        let (w_rel_tx, w_rel_rx) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_w, move || {
                w_acq_tx.send(()).unwrap();
                w_rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        // Give the writer a beat to grab writer-intent and block on data.
        std::thread::sleep(Duration::from_millis(200));

        // Step 3: NEW reader arrives. Under the turnstile, it must
        // block at writer-intent (writer holds it exclusive) and
        // NOT acquire ahead of the queued writer.
        let lock_path_r2 = lock_path;
        let r2_done = Arc::new(AtomicUsize::new(0));
        let r2_done_t = r2_done.clone();
        let r2 = std::thread::spawn(move || {
            with_shared_lock(&lock_path_r2, move || {
                r2_done_t.fetch_add(1, Ordering::SeqCst);
                Ok::<_, LpmError>(())
            })
        });
        // Give the new reader plenty of polling cycles to attempt
        // acquisition. Without the turnstile, it would race past the
        // queued writer and complete here.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            r2_done.load(Ordering::SeqCst),
            0,
            "late reader must NOT acquire while a writer is queued behind in-flight readers \
             (writer-starvation regression)",
        );

        // Step 4: release r1 → writer can finally take data-exclusive.
        r1_rel_tx.send(()).unwrap();
        r1.join().unwrap().unwrap();

        // Writer should acquire and signal.
        w_acq_rx.recv().unwrap();
        // r2 is still blocked because writer holds the gate.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            r2_done.load(Ordering::SeqCst),
            0,
            "late reader must remain blocked while writer is in critical section",
        );

        // Step 5: release writer → r2 acquires.
        w_rel_tx.send(()).unwrap();
        writer.join().unwrap().unwrap();
        r2.join().unwrap().unwrap();
        assert_eq!(
            r2_done.load(Ordering::SeqCst),
            1,
            "late reader must complete after writer releases",
        );
    }

    /// The intent-gate file is created automatically alongside the
    /// data lock — pin its location so docs and external tooling can
    /// rely on the convention.
    #[test]
    fn writer_intent_path_appended_to_data_path_filename() {
        let derived = writer_intent_path_for(Path::new("/tmp/lpm/store/.gc.lock"));
        assert_eq!(
            derived,
            PathBuf::from("/tmp/lpm/store/.gc.lock.writer-intent")
        );
    }

    /// The writer-queue baton file is also derived from the data lock
    /// path. Pin its location for the same reason.
    #[test]
    fn writer_queue_path_appended_to_data_path_filename() {
        let derived = writer_queue_path_for(Path::new("/tmp/lpm/store/.gc.lock"));
        assert_eq!(
            derived,
            PathBuf::from("/tmp/lpm/store/.gc.lock.writer-queue")
        );
    }

    /// Multi-writer preference: when W1 is in the body and W2 has
    /// queued behind data-exclusive, NEW readers must NOT be able to
    /// leapfrog W2 between W1's release and W2's acquire. Without the
    /// writer-queue baton, the reader-vs-W2 race on gate-exclusive
    /// has no SH-vs-EX fairness guarantee from the kernel and W2 can
    /// starve under reader pressure.
    ///
    /// This scenario was possible before the writer-queue baton.
    #[test]
    fn second_writer_not_leapfrogged_by_late_readers() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("test.lock");

        // Step 1: W1 takes the exclusive lock and holds it.
        let lock_path_w1 = lock_path.clone();
        let (w1_acq_tx, w1_acq_rx) = std::sync::mpsc::channel::<()>();
        let (w1_rel_tx, w1_rel_rx) = std::sync::mpsc::channel::<()>();
        let w1 = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_w1, move || {
                w1_acq_tx.send(()).unwrap();
                w1_rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        w1_acq_rx.recv().unwrap();

        // Step 2: W2 arrives and queues. It will:
        //   - acquire writer-queue shared (alongside W1's queue-shared),
        //   - block on writer-intent exclusive (W1 holds it).
        let lock_path_w2 = lock_path.clone();
        let w2_done = Arc::new(AtomicUsize::new(0));
        let w2_done_t = w2_done.clone();
        let (w2_rel_tx, w2_rel_rx) = std::sync::mpsc::channel::<()>();
        let w2 = std::thread::spawn(move || {
            with_exclusive_lock(&lock_path_w2, move || {
                w2_done_t.fetch_add(1, Ordering::SeqCst);
                w2_rel_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        // Give W2 a beat to take queue-shared and block on intent.
        std::thread::sleep(Duration::from_millis(200));

        // Step 3: a wave of readers arrives AFTER W2 has queued.
        // Without the queue baton, when W1 releases gate, the readers
        // could race past W2 on gate-shared and starve W2.
        let mut reader_handles = Vec::new();
        let readers_done = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let lock_path_r = lock_path.clone();
            let counter = readers_done.clone();
            reader_handles.push(std::thread::spawn(move || {
                with_shared_lock(&lock_path_r, move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, LpmError>(())
                })
            }));
        }

        // Step 4: release W1. The reader-vs-W2 race window opens here.
        // With the queue baton in place, readers see W2's queue-shared
        // and back off; W2 acquires next.
        w1_rel_tx.send(()).unwrap();
        w1.join().unwrap().unwrap();

        // Give the system time for either W2 OR readers to acquire
        // (whichever wins the race). Wait long enough that the
        // 100ms-poll-interval scheduling is well past.
        std::thread::sleep(Duration::from_millis(500));

        // Assertion: W2 must have run, NOT the readers.
        assert_eq!(
            w2_done.load(Ordering::SeqCst),
            1,
            "second writer must acquire after first writer releases, not be leapfrogged \
             by the queued reader wave",
        );
        assert_eq!(
            readers_done.load(Ordering::SeqCst),
            0,
            "readers queued behind a queued writer must NOT acquire ahead of that writer",
        );

        // Step 5: release W2 → readers finally acquire.
        w2_rel_tx.send(()).unwrap();
        w2.join().unwrap().unwrap();
        for h in reader_handles {
            h.join().unwrap().unwrap();
        }
        assert_eq!(
            readers_done.load(Ordering::SeqCst),
            3,
            "all queued readers must acquire after the writer chain drains",
        );
    }
}
