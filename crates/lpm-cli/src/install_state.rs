//! Sync-safe install-state check shared by the top-of-main fast lane,
//! `install.rs`, and `dev.rs`. Single source of truth — never duplicate.
//!
//! extracted from `install.rs::is_install_up_to_date()`
//! and `dev.rs::compute_install_hash()` / `dev.rs::needs_install()`.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Atomically write a small state file with owner-only perms (0o600 on Unix).
///
/// `install-hash` is the freshness short-circuit `lpm dev` and the
/// install fast lane consult to decide whether to re-link. On shared
/// hosts a default-umask (0o644) write lets any local uid forge or
/// truncate the file and either trigger a re-install loop or coerce
/// the fast lane to short-circuit a stale tree as fresh. Atomic
/// rename + 0o600 closes both shapes; on non-Unix the rename is
/// still atomic but the perms knob is a no-op.
fn write_state_file_owner_only(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "state file has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "state file path has no file name",
        )
    })?;
    let tmp_name = format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        std::process::id()
    );
    let tmp = parent.join(tmp_name);

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }
    {
        let mut f = open_opts.open(&tmp)?;
        std::io::Write::write_all(&mut f, content)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Result of checking install state.
pub struct InstallState {
    /// Whether the project's install is up to date.
    pub up_to_date: bool,
    /// SHA-256 hex digest of `package.json + "\0" + lpm.lock`.
    /// `None` only when package.json doesn't exist or can't be read from disk.
    /// `Some` when the file exists and is readable — even if the content is
    /// invalid JSON or fails typed parsing. This distinction matters for
    /// `dev.rs::needs_install()`: `None` → "nothing to install" (no manifest),
    /// `Some` + `!up_to_date` → "needs install" (triggers full pipeline which
    /// surfaces any parse errors).
    pub hash: Option<String>,
}

/// Schema tag prefix baked into every install-hash. Bump when the install
/// pipeline's semantics change in a way that makes a previously up-to-date
/// project NOT up to date under the new rules — even if the manifest and
/// lockfile bytes are identical.
///
/// History:
/// - `v1`: original hash (pkg + lock).
/// - `v2` : `lpm install` now resolves `devDependencies` in
///   addition to `dependencies`. Projects whose previous install silently
///   dropped devDeps must be treated as stale so the next bare `lpm install`
///   runs the full pipeline and populates them. Without this bump, an
///   existing up-to-date install would skip the pipeline and leave devDeps
///   unresolved until the manifest changes for some other reason.
/// - `v3` (day-3, F7a): the hash now folds in every file:/link:
///   directory dep's `package.json` content (recursively, depth-3 + realpath
///   cycle-detect). Without this, edits to a local source's `package.json`
///   (e.g., adding a new `dependencies` entry, bumping the source's own
///   version) would leave `lpm install`'s up-to-date check returning `true`
///   even though the install needs to be re-run. The schema bump invalidates
///   every v2 install-hash on disk on the first post-upgrade install — same
///   posture as the v1→v2 bump.
// bumped v4 → v5.
//
// Round-5 (v3 → v4) invalidated caches because the SET of root
// symlinks expanded; round-6 (v4 → v5) invalidates because the SET
// OF INPUTS the hash folds in expanded. [`collect_file_link_manifest_bytes`]
// now also folds in every workspace member's package.json so a
// member's manifest edit (e.g., adding `bar: workspace:*` to a
// sibling) is visible to the freshness check. Pre-round-6, the same
// edit left the install-hash unchanged, the next install hit the
// "up to date" fast-exit, and the auditor's HIGH 1 repro showed
// `node_modules/bar` never landed.
//
// **v6 — linker mode folds into the hash.** Pre-v6 the install-hash
// only keyed off manifest/lock content, so a post-install change to
// `LPM_LINKER` or `~/.lpm/config.toml > linker` left the hash matching
// and the "up to date" fast-exit fired — silently leaving the project
// on the prior layout with no re-link. v6 includes the resolved linker
// mode (via `compute_install_hash_v6`) AND the install-hash file gains
// an `l:<isolated|hoisted>` line so the mtime fast path can detect a
// linker change without recomputing the full hash. Same upgrade
// posture as v3→v4→v5: existing v5 hashes mismatch on first read and
// trigger one full re-resolve, after which the v6 cache is warm.
const INSTALL_HASH_SCHEMA_TAG: &[u8] = b"lpm-install-hash-v6\x00";

/// Compute the install hash from raw file contents — back-compat shim
/// that defaults file/link bytes to empty AND linker mode to the
/// active default. Used by test fixtures and `dev.rs`'s
/// deterministic-hash unit tests where the linker is not under test.
/// Production callers use [`compute_install_hash_v6`] directly.
///
/// flipped [`LinkerMode::default`] from Isolated to
/// Hoisted; this shim follows the flip so callers expecting "the hash
/// for a default install" get the post-4f shape.
pub fn compute_install_hash(pkg_content: &str, lock_content: &str) -> String {
    compute_install_hash_v6(
        pkg_content,
        lock_content,
        &[],
        lpm_linker::LinkerMode::default(),
    )
}

/// Same shape as [`compute_install_hash_v6`] minus the linker arg —
/// retained ONLY to keep the v3 name available to callers that
/// explicitly want the active default. Behaves identically to
/// `compute_install_hash_v6(..., LinkerMode::default())`. New code
/// should call `compute_install_hash_v6` and pass the resolved mode.
pub fn compute_install_hash_v3(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
) -> String {
    compute_install_hash_v6(
        pkg_content,
        lock_content,
        file_link_manifests,
        lpm_linker::LinkerMode::default(),
    )
}

/// Full install hash with manifest content + lockfile + file/link
/// manifests + resolved linker mode folded in.
///
/// Including linker in the hash closes the post-install env/config
/// freshness gap: if a user runs `lpm install` once with the default
/// isolated layout and then sets `LPM_LINKER=hoisted`, pre-v6 the hash
/// stayed the same and the "up to date" fast-exit fired — leaving
/// the project on isolated despite the requested switch. v6 keys the
/// hash on the resolved linker so any flip invalidates the cache.
///
/// Order discipline: `schema_tag || pkg || \0 || lock || \0 || flb ||
/// \0 || linker`. Each section is preceded by an explicit `\0` domain
/// separator so a future caller can't construct an ambiguous input.
/// The linker byte is the canonical string from [`LinkerMode::as_str`]
/// (`"isolated"` or `"hoisted"`).
pub fn compute_install_hash_v6(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
    linker_mode: lpm_linker::LinkerMode,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INSTALL_HASH_SCHEMA_TAG);
    hasher.update(pkg_content.as_bytes());
    hasher.update(b"\x00"); // domain separator prevents "ab"+"cd" == "abc"+"d"
    hasher.update(lock_content.as_bytes());
    hasher.update(b"\x00");
    hasher.update(file_link_manifests);
    hasher.update(b"\x00");
    hasher.update(linker_mode.as_str().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// collect file:/link: directory dep
/// `package.json` bytes for the install-hash freshness signal.
///
/// Walks the consumer's package.json `dependencies` /
/// `devDependencies` / `peerDependencies` / `optionalDependencies` for
/// `file:` and `link:` specifiers pointing at directories (file:
/// tarballs are skipped — their content is integrity-locked elsewhere
/// in the install pipeline; only directory sources have mutable
/// content that can drift between installs).
///
/// For each directory dep:
///   1. Realpath the source against `project_dir`.
///   2. Read its `package.json` content.
///   3. Recurse into the source's own file:/link: directory deps,
///      bounded at depth 3 with realpath cycle-detect.
///
/// Returns a deterministically-ordered byte buffer:
/// `path1 || \0 || pkg1 || \0 || path2 || \0 || pkg2 || \0 || …`
/// where paths are SORTED by realpath byte order. Empty for projects
/// without local-source deps (the common case — keeps the v2 hash
/// hot path semantically unchanged).
///
/// Errors silently degrade to skipping the offending entry — an
/// unparseable manifest, a missing source dir, or a JSON shape that
/// doesn't have a deps map all return empty bytes for that node.
/// The trade-off: a corrupted local-source manifest doesn't block the
/// up-to-date check; the install pipeline downstream still surfaces
/// the corruption with a typed error.
///
/// Depth bound matches umbrella prepare-runner posture: 3.
/// Realpath cycle-detect prevents `A → B → A` infinite loops.
pub fn collect_file_link_manifest_bytes(
    project_dir: &std::path::Path,
    pkg_content: &str,
) -> Vec<u8> {
    let mut visited: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    let mut buf: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
    let mut freshness_files: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();

    if let Some(path) = nearest_pnpm_workspace_yaml(project_dir) {
        push_freshness_file(path, &mut freshness_files, &mut buf);
    }

    walk_file_link_deps(project_dir, pkg_content, 0, 3, &mut visited, &mut buf);

    // **audit response (round 6) — workspace member
    // manifests fold into the install-hash.** Round-5's workspace-
    // member BFS expands the root-symlink set based on each linked
    // member's `workspace:` transitives, but pre-round-6 the install-
    // hash didn't fold in member manifests at all. Adding `bar:
    // workspace:*` to a member's manifest left the install-hash
    // unchanged, so the next install hit the "up to date" fast-exit
    // and never planted `node_modules/bar`. This block discovers the
    // workspace from `project_dir` and folds every member's
    // package.json into the buffer (deduped against any member that
    // was ALREADY visited as a file:/link: dep). It also walks each
    // member's file:/link: transitives so file: deps DECLARED inside
    // member manifests participate in the freshness signal too.
    //
    // Errors silently degrade (no workspaces field / unparseable
    // package.json / canonicalize failure) — same posture as the
    // outer walker.
    if let Ok(Some(ws)) = lpm_workspace::discover_workspace(project_dir) {
        push_freshness_file(
            ws.root.join("pnpm-workspace.yaml"),
            &mut freshness_files,
            &mut buf,
        );

        for member in &ws.members {
            let Ok(realpath) = member.path.canonicalize() else {
                continue;
            };
            if !visited.insert(realpath.clone()) {
                continue; // already covered via file:/link:
            }
            let pkg_json_path = realpath.join("package.json");
            let Ok(member_content) = std::fs::read_to_string(&pkg_json_path) else {
                continue;
            };
            buf.push((realpath.clone(), member_content.as_bytes().to_vec()));
            // Walk file:/link: transitives declared inside the member's
            // manifest — those manifests' contents must also affect
            // the freshness signal so a `file:` external dep edited
            // in place invalidates the cache.
            walk_file_link_deps(&realpath, &member_content, 0, 3, &mut visited, &mut buf);
        }
    }

    // Sort by realpath byte order for deterministic output across
    // platforms / hash-map iteration orders.
    buf.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    for (path, content) in buf {
        out.extend_from_slice(path.to_string_lossy().as_bytes());
        out.push(0);
        out.extend_from_slice(&content);
        out.push(0);
    }
    out
}

fn nearest_pnpm_workspace_yaml(project_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = Some(project_dir);
    while let Some(dir) = current {
        let candidate = dir.join("pnpm-workspace.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

pub fn has_pnpm_workspace_yaml(project_dir: &std::path::Path) -> bool {
    nearest_pnpm_workspace_yaml(project_dir).is_some()
}

fn push_freshness_file(
    path: std::path::PathBuf,
    seen: &mut std::collections::HashSet<std::path::PathBuf>,
    buf: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
) {
    let Ok(content) = std::fs::read(&path) else {
        return;
    };
    let key = path.canonicalize().unwrap_or(path);
    if seen.insert(key.clone()) {
        buf.push((key, content));
    }
}

fn walk_file_link_deps(
    base_dir: &std::path::Path,
    pkg_content: &str,
    depth: u32,
    max_depth: u32,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    buf: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
) {
    if depth >= max_depth {
        return;
    }
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(pkg_content) else {
        return;
    };
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(deps) = pkg.get(field).and_then(|v| v.as_object()) else {
            continue;
        };
        for (_name, raw) in deps {
            let Some(raw_str) = raw.as_str() else {
                continue;
            };
            let path_str = if let Some(p) = raw_str.strip_prefix("file:") {
                p
            } else if let Some(p) = raw_str.strip_prefix("link:") {
                p
            } else {
                continue;
            };
            let abs = base_dir.join(path_str);
            // Only directory sources participate in F7a. file: tarballs
            // are content-integrity-locked elsewhere; their bytes don't
            // drift between installs without a corresponding lockfile
            // entry rewrite.
            let Ok(meta) = std::fs::metadata(&abs) else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let Ok(realpath) = abs.canonicalize() else {
                continue;
            };
            if !visited.insert(realpath.clone()) {
                continue; // realpath cycle — skip
            }
            let Ok(manifest_content) = std::fs::read_to_string(realpath.join("package.json"))
            else {
                continue;
            };
            buf.push((realpath.clone(), manifest_content.as_bytes().to_vec()));
            // Recurse into this dep's own file/link deps. The recursive
            // base_dir is the source's realpath, NOT the consumer's
            // project_dir — relative paths in the source's package.json
            // resolve against the source's directory.
            walk_file_link_deps(
                &realpath,
                &manifest_content,
                depth + 1,
                max_depth,
                visited,
                buf,
            );
        }
    }
}

/// Full up-to-date predicate with the strongest semantics:
///
/// 1. All four artifacts must exist: package.json, lpm.lock, node_modules, .lpm/install-hash
/// 2. Hash of (package.json + lpm.lock) must match cached hash
/// 3. node_modules mtime must be ≤ install-hash mtime (detects external modifications)
///
/// Returns `InstallState` with the computed hash for downstream reuse.
///
/// fast path: when the install-hash file contains an optional
/// mtime line (written by [`write_install_hash`]) and the recorded
/// mtimes of package.json + lpm.lock still match, skips the hash
/// recomputation entirely — saving one file read of each manifest plus
/// the SHA-256 pass. On any mismatch (or absent mtime line) falls
/// through to the full-read path.
pub fn check_install_state(project_dir: &Path) -> InstallState {
    let pkg_json = project_dir.join("package.json");
    if !pkg_json.exists() {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    }

    // Read package.json + resolve linker BEFORE any freshness comparison.
    // pkg-read failure → no readable manifest, return hash=None.
    let Ok(pkg_content) = std::fs::read_to_string(&pkg_json) else {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    };

    #[cfg(test)]
    let cfg = crate::commands::config::GlobalConfig::empty();
    #[cfg(not(test))]
    let cfg = crate::commands::config::GlobalConfig::load();
    let linker_mode = match crate::linker_config::resolve_effective_linker_from_bytes(
        None,
        &pkg_content,
        &cfg,
        project_dir,
    ) {
        Ok(mode) => mode,
        Err(_) => return invalid_linker_state(project_dir, &pkg_content),
    };

    // Single mtime probe lives inside `check_install_state_with_linker`
    // — no pre-delegation probe here, otherwise the stale path would
    // pay the same filesystem checks twice (once on the early bail,
    // once after delegation re-runs them).
    check_install_state_with_linker(project_dir, &pkg_content, linker_mode)
}

/// Same semantics as [`check_install_state`] but accepts a pre-read
/// `package.json` content from the caller — used by the top-of-main
/// fast lane which already read the file for the workspace-root check.
/// Saves one redundant file read. Linker resolution still runs
/// internally with `cli_override = None`.
pub fn check_install_state_with_content(project_dir: &Path, pkg_content: &str) -> InstallState {
    #[cfg(test)]
    let cfg = crate::commands::config::GlobalConfig::empty();
    #[cfg(not(test))]
    let cfg = crate::commands::config::GlobalConfig::load();
    let linker_mode = match crate::linker_config::resolve_effective_linker_from_bytes(
        None,
        pkg_content,
        &cfg,
        project_dir,
    ) {
        Ok(mode) => mode,
        Err(_) => return invalid_linker_state(project_dir, pkg_content),
    };
    check_install_state_with_linker(project_dir, pkg_content, linker_mode)
}

/// Invalid-linker freshness signal. Shared by [`check_install_state`]
/// and [`check_install_state_with_content`]: when the env / config /
/// `package.json` linker chain has a syntactically invalid value, the
/// freshness predicate must NOT short-circuit as up-to-date — the
/// trailing install pipeline is the seam that surfaces the parse error.
///
/// Returns `up_to_date: false` (never up-to-date when config is
/// broken) with a `hash: Some(_)` placeholder computed against
/// `LinkerMode::Isolated`. The `Some` matters: `dev.rs::needs_install`
/// treats `hash: None` as "no package.json" and skips the install
/// step entirely, which would silently mask the linker error from a
/// user running `lpm dev`. With a placeholder hash, dev triggers the
/// install attempt that fails loud — same posture as `lpm install`.
fn invalid_linker_state(project_dir: &Path, pkg_content: &str) -> InstallState {
    let lock_content = std::fs::read_to_string(project_dir.join("lpm.lock")).unwrap_or_default();
    let file_link_bytes = collect_file_link_manifest_bytes(project_dir, pkg_content);
    let placeholder = compute_install_hash_v6(
        pkg_content,
        &lock_content,
        &file_link_bytes,
        lpm_linker::LinkerMode::Isolated,
    );
    InstallState {
        up_to_date: false,
        hash: Some(placeholder),
    }
}

/// Same as [`check_install_state_with_content`] but takes a
/// pre-resolved linker mode from the caller. Used by the install
/// pipeline, which already resolved the linker (and validated it
/// fail-loud) for its own dispatch — saves a duplicate resolution.
pub fn check_install_state_with_linker(
    project_dir: &Path,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
) -> InstallState {
    // mtime short-circuit also applies here. The caller may have
    // already read pkg.json for an earlier check, but the fast path still
    // skips the read of lpm.lock + the SHA-256 pass.
    if let Some(state) = try_mtime_fast_path(project_dir, pkg_content, linker_mode) {
        return state;
    }

    let lock_path = project_dir.join("lpm.lock");
    let hash_file = project_dir.join(".lpm").join("install-hash");
    let nm = project_dir.join("node_modules");

    // Read lockfile — empty string if missing (hash will mismatch → needs install)
    let lock_content = std::fs::read_to_string(&lock_path).unwrap_or_default();
    // day-3 (F7a): fold file:/link: directory dep
    // package.json content into the install hash. Empty bytes for
    // projects without local-source deps — matches the v2 semantic
    // (modulo the schema-tag bump invalidating v2 caches once).
    let file_link_bytes = collect_file_link_manifest_bytes(project_dir, pkg_content);
    let current_hash =
        compute_install_hash_v6(pkg_content, &lock_content, &file_link_bytes, linker_mode);

    // Validate that package.json parses into the typed PackageJson struct —
    // the same deserialization the full install path uses via read_package_json().
    // A generic serde_json::Value check is NOT sufficient: it accepts invalid
    // LPM config values that the typed parse must still reject.
    //
    // The hash is still returned as Some so callers like dev.rs::needs_install()
    // know the file exists and can trigger a full install which surfaces the error.
    if serde_json::from_str::<lpm_workspace::PackageJson>(pkg_content).is_err() {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // If any artifact is missing, we need install but still return the hash
    if !nm.exists() || !hash_file.exists() || !lock_path.exists() {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    if binary_lockfile_sidecar_needs_refresh(project_dir) {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // D8c — layout-aware freshness gate. If the project is
    // on the legacy `node_modules/.lpm/` wrapper layout but the new
    // `<project>/.lpm/wrappers/` root is empty, the install is NOT
    // fresh regardless of hash/mtime match. This is the upgrade-in-
    // place path: user updated their `lpm-rs` binary without wiping
    // node_modules, hash still matches, but the wrapper layout is
    // owed a migration. Without this gate the top-of-`main` fast lane
    // would short-circuit and the migration code in `lpm install`
    // would never run.
    if lpm_linker::LayoutPaths::for_project(project_dir).needs_layout_migration() {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // — v1 → v2 store-layout migration gate. After
    // the default flip, an upgrade-in-place user (still with
    // v1's `<project>/.lpm/wrappers/` or `<project>/.lpm/hoisted/`
    // populated) needs the install pipeline to run the v1→v2 wipe-
    // and-rebuild sequence. Without this gate the sync fast lane in
    // `main.rs` short-circuits with "up to date" and the user's
    // project stays on the legacy layout indefinitely. The dual-gate
    // shape mirrors D8c: legacy state populated + new
    // store version active = freshness reset.
    //
    // Detection mirrors the install-pipeline's
    // [`commands::install::needs_v2_migration`] but is duplicated
    // here intentionally: importing the install module from
    // install_state would create a cyclic-ish coupling for one
    // two-line predicate, and the predicate is small enough that
    // drift won't realistically diverge.
    if lpm_store::StoreVersion::from_env().is_v2() {
        let legacy_isolated = project_dir.join(".lpm").join("wrappers");
        let legacy_hoisted = project_dir.join(".lpm").join("hoisted");
        if legacy_isolated.exists() || legacy_hoisted.exists() {
            return InstallState {
                up_to_date: false,
                hash: Some(current_hash),
            };
        }
    }

    // Hash comparison — read only the first line of the file so v1 (bare
    // hash) and v2 (hash + mtime line) formats both parse identically.
    let Ok(cached_hash_file) = std::fs::read_to_string(&hash_file) else {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    };
    let cached_hash = cached_hash_file.lines().next().unwrap_or("").trim();
    if cached_hash != current_hash {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // Shallow mtime check: node_modules modified after hash file → external change
    let up_to_date = match (
        std::fs::metadata(&nm).and_then(|m| m.modified()),
        std::fs::metadata(&hash_file).and_then(|m| m.modified()),
    ) {
        (Ok(nm_t), Ok(hash_t)) => nm_t <= hash_t,
        _ => false,
    };

    InstallState {
        up_to_date,
        hash: Some(current_hash),
    }
}

/// mtime short-circuit for the up-to-date check.
///
/// Reads `.lpm/install-hash`; when it contains a v2 mtime line
/// (`m:<pkg_ns>:<lock_ns>`) and the recorded mtimes still match the
/// current mtimes of `package.json` and `lpm.lock`, declares the
/// install up to date without reading either manifest or recomputing
/// the hash. Returns `None` on ANY deviation — the caller then falls
/// through to the full hash path, which is still correct.
///
/// Safety: only TRUSTS the stored hash when mtimes match. An adversary
/// who can rewrite the file's manifest bytes also changes its mtime
/// (any `fs::write` updates mtime); the only way to defeat this check
/// is deliberate mtime tampering (`touch -t ...`), which is also
/// sufficient to defeat npm/pnpm/bun. Acceptable tradeoff.
///
/// when `.lpm/has-local-sources` exists,
/// the project has file:/link: directory deps whose `package.json`
/// content participates in the install hash. The mtime fast path
/// only tracks the consumer's `package.json` + `lpm.lock` mtimes,
/// not local-source manifest mtimes — so a local-source edit would
/// otherwise be invisible to the fast path. Bail to the slow path
/// (which calls [`collect_file_link_manifest_bytes`] and recomputes
/// the v3 hash) whenever the sentinel is present. The single-stat
/// cost is negligible compared to the fast path's ~4 stats.
fn try_mtime_fast_path(
    project_dir: &Path,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
) -> Option<InstallState> {
    let nm = project_dir.join("node_modules");
    if !nm.exists() {
        return None;
    }

    if package_json_needs_slow_freshness(pkg_content) || has_pnpm_workspace_yaml(project_dir) {
        return None;
    }

    // day-3 (F7a) — sentinel for "this project has local-
    // source deps; the fast path can't trust mtimes alone."
    let local_sources_sentinel = project_dir.join(".lpm").join("has-local-sources");
    if local_sources_sentinel.exists() {
        return None;
    }

    // D8c — bail to the slow path when a layout migration
    // is owed. The slow path's existence-check guard gates the same
    // predicate, but the mtime fast path skips that guard entirely
    // when manifest mtimes match. Returning `None` here forces the
    // caller to fall through to `check_install_state_with_content`
    // where the migration gate fires and `up_to_date = false` is
    // returned.
    if lpm_linker::LayoutPaths::for_project(project_dir).needs_layout_migration() {
        return None;
    }

    // — v1 → v2 store migration gate. Must mirror
    // the slow-path guard in `check_install_state_with_content`
    // because the mtime fast lane skips that function entirely on
    // mtime hits. Without this, an upgrade-in-place user whose
    // package.json + lpm.lock mtimes haven't changed would
    // permanently short-circuit at "up to date" and never run the
    // v1 → v2 wipe-and-rebuild sequence.
    if lpm_store::StoreVersion::from_env().is_v2() {
        let legacy_isolated = project_dir.join(".lpm").join("wrappers");
        let legacy_hoisted = project_dir.join(".lpm").join("hoisted");
        if legacy_isolated.exists() || legacy_hoisted.exists() {
            return None;
        }
    }

    let hash_file = project_dir.join(".lpm").join("install-hash");
    let content = std::fs::read_to_string(&hash_file).ok()?;

    let mut lines = content.lines();
    let stored_hash = lines.next()?.trim();
    // v1 files have no second line → no mtime fast path available.
    let mtime_line = lines.next()?;
    let rest = mtime_line.strip_prefix("m:")?;
    let (pkg_ns_str, lock_ns_str) = rest.split_once(':')?;
    let stored_pkg_ns: u64 = pkg_ns_str.parse().ok()?;
    let stored_lock_ns: u64 = lock_ns_str.parse().ok()?;

    // v6: the install-hash gains an `l:<linker_mode>` line so the mtime
    // fast path can detect a post-install env/config linker flip
    // without recomputing the full SHA-256 over the manifest. Absent
    // line → legacy v5-or-earlier file → bail to slow path; the v6
    // schema tag will then mismatch and force re-install.
    let linker_line = lines.next()?;
    let stored_linker = linker_line.strip_prefix("l:")?;
    if stored_linker != linker_mode.as_str() {
        return None;
    }

    let pkg_ns = mtime_ns(&project_dir.join("package.json"))?;
    // lpm.lock may be absent on a never-installed fast-lane entry; 0
    // sentinel lines up with the writer's convention.
    let lock_ns = mtime_ns(&project_dir.join("lpm.lock")).unwrap_or(0);

    if pkg_ns != stored_pkg_ns || lock_ns != stored_lock_ns {
        return None;
    }

    if binary_lockfile_sidecar_needs_refresh(project_dir) {
        return None;
    }

    // External-modification check: if anything under node_modules was
    // touched more recently than the hash file, the recorded state
    // cannot be trusted even with matching manifest mtimes.
    let nm_ns = mtime_ns(&nm)?;
    let hash_ns = mtime_ns(&hash_file)?;
    if nm_ns > hash_ns {
        return None;
    }

    Some(InstallState {
        up_to_date: true,
        hash: Some(stored_hash.to_string()),
    })
}

fn package_json_needs_slow_freshness(pkg_content: &str) -> bool {
    pkg_content.contains("\"file:")
        || pkg_content.contains("\"link:")
        || pkg_content.contains("\"workspaces\"")
}

/// Return the modified-time of `path` as nanoseconds since the Unix
/// epoch. Returns `None` if the file is missing or the filesystem does
/// not expose mtime (neither of which should happen for the files the
/// install-state machinery cares about).
fn mtime_ns(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    // `as_nanos` returns u128; narrow to u64 — safe until year 2554.
    Some(dur.as_nanos() as u64)
}

fn binary_lockfile_sidecar_needs_refresh(project_dir: &Path) -> bool {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if !lockfile_path.exists() {
        return false;
    }

    let binary_path = lockfile_path.with_extension("lockb");
    match lpm_lockfile::BinaryLockfileReader::open(&binary_path) {
        Ok(Some(_)) => binary_lockfile_is_older_than_toml(&lockfile_path, &binary_path),
        Ok(None) => binary_lockfile_absence_requires_refresh(&lockfile_path),
        Err(_) => true,
    }
}

fn binary_lockfile_absence_requires_refresh(lockfile_path: &Path) -> bool {
    let Ok(lockfile) = lpm_lockfile::Lockfile::read_from_file(lockfile_path) else {
        return false;
    };
    lpm_lockfile::binary::binary_format_supports(&lockfile)
}

fn binary_lockfile_is_older_than_toml(lockfile_path: &Path, binary_path: &Path) -> bool {
    match (
        lockfile_path.metadata().and_then(|m| m.modified()),
        binary_path.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(toml_time), Ok(binary_time)) => binary_time < toml_time,
        _ => true,
    }
}

/// Write `.lpm/install-hash` in the v6 format (hash line + mtime line +
/// linker line). Callers provide the pre-computed hash AND the linker
/// mode that was effective for the install — both are needed so the
/// mtime fast path can detect a post-install env/config linker flip
/// without recomputing the full SHA-256.
///
/// On any failure reading an mtime (typically missing lpm.lock on a
/// dependency-less project), falls back to a `0` sentinel. A mismatch
/// between `0`-stored and a later real mtime simply falls through to
/// the full hash path — still correct, just not fast.
///
/// Writes `.lpm/install-hash` atomically via `fs::write`, same as the
/// prior byte-string-only writes — the ManifestTransaction snapshot
/// machinery is unaffected.
pub fn write_install_hash(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
) -> std::io::Result<()> {
    let pkg_ns = mtime_ns(&project_dir.join("package.json")).unwrap_or(0);
    let lock_ns = mtime_ns(&project_dir.join("lpm.lock")).unwrap_or(0);

    let hash_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&hash_dir)?;
    let linker_str = linker_mode.as_str();
    let content = format!("{hash}\nm:{pkg_ns}:{lock_ns}\nl:{linker_str}\n");
    write_state_file_owner_only(&hash_dir.join("install-hash"), content.as_bytes())?;

    // day-3 (F7a) + round-6 audit response — manage the
    // "needs-slow-path" sentinel.
    //
    // The mtime fast path checks ONLY root package.json + lpm.lock
    // mtimes — fast and correct for projects whose freshness signal
    // doesn't reach into other manifests. For projects with file: /
    // link: deps (round-3) OR with workspace members (round-6), the
    // install-hash also folds in those manifests' contents, and the
    // mtime fast path can't observe their changes. The sentinel
    // bails the fast path to the slow recompute in those cases.
    //
    // Pre-round-6 the sentinel was named `has-local-sources` and only
    // fired for file: / link: deps. Round-6 broadens its scope to
    // also include workspace members — a workspace root with no
    // file:/link: deps but with `workspaces: ["packages/*"]` declared
    // and a member that adds `bar: workspace:*` would (pre-fix) hit
    // the mtime fast path because the root's mtime is unchanged. The
    // file name is preserved for backward compat with on-disk state
    // from round-5 installs (a stale `has-local-sources` is harmless
    // — it just bails the fast path until the next install rewrites
    // it).
    //
    // The string-search is conservative: false positives (a string
    // `"file:` appearing in a description or homepage URL, or a
    // `workspaces` field in a non-workspace tool config) bail the
    // fast path → still correct, just slightly slower. False
    // negatives are impossible for the file: / link: case: every
    // such spec is `"<key>": "file:..."` / `"<key>": "link:..."`.
    let sentinel = hash_dir.join("has-local-sources");
    let needs_slow_path = std::fs::read_to_string(project_dir.join("package.json"))
        .is_ok_and(|s| package_json_needs_slow_freshness(&s))
        || has_pnpm_workspace_yaml(project_dir);
    if needs_slow_path {
        write_state_file_owner_only(&sentinel, b"")?;
    } else if sentinel.exists() {
        // Project transitioned away from a slow-path-required shape
        // (e.g., a `lpm uninstall` of the only file: dep, or removal
        // of the `workspaces` field). Sweep the sentinel so the fast
        // path can short-circuit on the next run.
        let _ = std::fs::remove_file(&sentinel);
    }
    Ok(())
}

/// Pre-clap argv gate for the top-of-main fast lane.
///
/// Returns `Some(json_mode)` if the fast lane should attempt the check.
/// Returns `None` if any disqualifying flag or argument is present.
///
/// Recognized install subcommands: "install", "i" (visible_alias).
///
/// Conservative: any unrecognized flag after "install" → fall through to
/// the full pipeline. This guarantees the fast lane never produces wrong
/// results — false negatives (falling through) are safe, false positives
/// (exiting early when we shouldn't) are not.
pub fn argv_qualifies_for_fast_lane() -> Option<bool> {
    // Use args_os() to avoid panicking on non-UTF-8 arguments.
    // Any argument that isn't valid UTF-8 causes a conservative bail
    // (fall through to the full pipeline where clap handles it).
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let args: Vec<&str> = raw_args
        .iter()
        .skip(1)
        .map(|a| a.to_str())
        .collect::<Option<Vec<_>>>()?;

    let mut json_mode = false;
    let mut found_install = false;

    for arg in &args {
        match *arg {
            "--json" => json_mode = true,

            // Global flags that change registry/auth behavior → disqualify.
            // --token and --registry take a value: disqualify on the flag itself.
            "--token" | "--registry" => return None,
            _ if arg.starts_with("--token=") || arg.starts_with("--registry=") => return None,
            "--insecure" => return None,

            // Harmless global flags — skip
            "--verbose" | "-v" => {}

            // The subcommand itself
            "install" | "i" if !found_install => found_install = true,

            // Install-specific flags that disqualify the fast lane.
            // ANY of these means semantics differ from a bare `lpm install`.
            "--force"
            | "--offline"
            | "--filter"
            | "-w"
            | "--workspace-root"
            | "--fail-if-no-match"
            | "--allow-new"
            | "--linker"
            | "--exact"
            | "--tilde"
            | "--save-prefix"
            | "-D"
            | "--save-dev"
            | "--no-skills"
            | "--no-editor-setup"
            | "--no-security-summary"
            | "--auto-build"
                if found_install =>
            {
                return None;
            }

            // Value-taking install flags (--linker <val>, --filter <val>, etc.)
            // already handled above — the flag itself disqualifies.

            // Any non-flag argument after "install" = positional package arg
            _ if found_install && !arg.starts_with('-') => return None,

            // Unknown flag after install — bail conservatively
            _ if found_install && arg.starts_with('-') => return None,

            // Something before "install" we don't recognize → not our command
            _ if !found_install => return None,

            _ => return None,
        }
    }

    if found_install { Some(json_mode) } else { None }
}

/// Conservative check for whether a package.json defines workspaces.
///
/// Uses raw string search to avoid JSON parsing overhead on the fast lane.
/// May produce false positives (e.g., `"workspaces"` in a description field),
/// which is safe — the fast lane falls through to the full pipeline.
/// False negatives are impossible — every workspace root package.json must
/// have `"workspaces"` as a JSON key.
pub fn is_likely_workspace_root(project_dir: &Path) -> bool {
    let pkg_json = project_dir.join("package.json");
    match std::fs::read_to_string(&pkg_json) {
        Ok(content) => is_workspace_root_content(&content),
        Err(_) => false,
    }
}

/// Same as [`is_likely_workspace_root`] but takes pre-read content.
/// lets the top-of-main fast lane amortize a single
/// `package.json` read across the workspace check and the install-state
/// check.
pub fn is_workspace_root_content(pkg_content: &str) -> bool {
    pkg_content.contains("\"workspaces\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn scoped_home_for(_path: &Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::update([("LPM_LINKER", None)])
    }

    fn setup_up_to_date_project() -> TempDir {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(
            &fs::read_to_string(p.join("package.json")).unwrap(),
            "lock-content",
        );
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();
        dir
    }

    #[test]
    fn up_to_date_returns_true() {
        let dir = setup_up_to_date_project();
        let _home = scoped_home_for(dir.path());
        let state = check_install_state(dir.path());
        assert!(state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_lockfile_returns_false_with_hash() {
        let dir = setup_up_to_date_project();
        let _home = scoped_home_for(dir.path());
        fs::remove_file(dir.path().join("lpm.lock")).unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        // Hash is still computed (with empty lock content)
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_node_modules_returns_false() {
        let dir = setup_up_to_date_project();
        let _home = scoped_home_for(dir.path());
        fs::remove_dir_all(dir.path().join("node_modules")).unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn changed_package_json_returns_false() {
        let dir = setup_up_to_date_project();
        let _home = scoped_home_for(dir.path());
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"b":"^2.0.0"}}"#,
        )
        .unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_package_json_returns_no_hash() {
        let dir = TempDir::new().unwrap();
        let _home = scoped_home_for(dir.path());
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        assert!(state.hash.is_none());
    }

    #[test]
    fn syntactically_invalid_json_returns_not_up_to_date() {
        // GPT audit round 1: a malformed package.json with a forged matching
        // install-hash must NOT exit the fast lane with "success: true".
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let bad_json = "this is not valid json {{{";
        let lock = "lock-content";
        fs::write(p.join("package.json"), bad_json).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(bad_json, lock);
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();

        let state = check_install_state(p);
        assert!(!state.up_to_date, "invalid JSON must not be up to date");
        // hash is Some because the file exists and is readable — dev.rs
        // needs this to trigger auto-install (which surfaces the error).
        assert!(state.hash.is_some(), "readable file should produce a hash");
    }

    #[test]
    fn semantically_invalid_lpm_config_returns_not_up_to_date() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let bad_shape = r#"{"lpm":{"catalogMode":"sometimes"}}"#;
        let lock = "lock-content";
        fs::write(p.join("package.json"), bad_shape).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(bad_shape, lock);
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();

        let state = check_install_state(p);
        assert!(
            !state.up_to_date,
            "semantically invalid lpm config must not be up to date"
        );
        assert!(
            state.hash.is_some(),
            "readable file should still produce a hash for dev.rs"
        );
    }

    #[test]
    fn pnpm_workspace_yaml_change_invalidates_matching_mtime_state() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg = r#"{"dependencies":{"is-positive":"catalog:"}}"#;
        let lock = "lock-content";
        fs::write(p.join("package.json"), pkg).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::write(
            p.join("pnpm-workspace.yaml"),
            "packages:\n  - \"packages/*\"\ncatalog:\n  is-positive: ^1.0.0\n",
        )
        .unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();

        let hash = compute_install_hash_v6(
            pkg,
            lock,
            &collect_file_link_manifest_bytes(p, pkg),
            lpm_linker::LinkerMode::default(),
        );
        let content = format!(
            "{hash}\nm:{}:{}\nl:{}\n",
            mtime_ns(&p.join("package.json")).unwrap(),
            mtime_ns(&p.join("lpm.lock")).unwrap(),
            lpm_linker::LinkerMode::default().as_str()
        );
        fs::write(p.join(".lpm").join("install-hash"), content).unwrap();

        fs::write(
            p.join("pnpm-workspace.yaml"),
            "packages:\n  - \"packages/*\"\ncatalog:\n  is-positive: ^2.0.0\n",
        )
        .unwrap();

        let state = check_install_state(p);
        assert!(
            !state.up_to_date,
            "pnpm-workspace.yaml drift must force the install pipeline"
        );
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = compute_install_hash("pkg1", "lock1");
        let h2 = compute_install_hash("pkg1", "lock1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_differs_with_different_content() {
        let h1 = compute_install_hash("pkg1", "lock1");
        let h2 = compute_install_hash("pkg2", "lock1");
        let h3 = compute_install_hash("pkg1", "lock2");
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn domain_separator_prevents_collision() {
        // "ab" + "\0" + "cd" != "a" + "\0" + "bcd"
        let h1 = compute_install_hash("ab", "cd");
        let h2 = compute_install_hash("a", "bcd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn schema_tag_is_baked_into_hash() {
        // Pin the hash of known inputs against the current schema tag so
        // that any accidental change to `INSTALL_HASH_SCHEMA_TAG` — or
        // removal of the `hasher.update(tag)` line — makes this test
        // fail loudly. The expected value below was computed from
        //   SHA256("lpm-install-hash-v6\x00" || "pkg" || "\x00" || "lock"
        //          || "\x00" || "\x00" || "isolated")
        // at the time the schema was bumped to v6 (post-install linker
        // freshness fold).
        //
        // note: `compute_install_hash` now defaults
        // to `LinkerMode::default()` which flipped to Hoisted in 4f.
        // To keep this test schema-pinned (not coupled to whichever
        // linker is the default), call `compute_install_hash_v6`
        // explicitly with `LinkerMode::Isolated` — the value used at
        // the time the schema was last bumped. Updating this constant
        // is a deliberate act that must accompany any schema-version
        // bump.
        let actual = compute_install_hash_v6("pkg", "lock", &[], lpm_linker::LinkerMode::Isolated);
        let expected_v6 = "3adc9b6970027883b955378cd3dc894ff3a40df5875b4f3150e42254d04b623e";
        assert_eq!(
            actual, expected_v6,
            "install-hash schema tag drift — bump INSTALL_HASH_SCHEMA_TAG and update this test \
             together. Current tag must produce the pinned hash for the fixed inputs."
        );
    }

    #[test]
    fn schema_tag_change_would_change_hash() {
        // Dual to the pin test above — prove the schema tag is
        // load-bearing. A v1 install-hash (no tag) of the same inputs
        // must NOT match the current v3 hash.
        fn v1_hash(pkg: &str, lock: &str) -> String {
            let mut h = Sha256::new();
            h.update(pkg.as_bytes());
            h.update(b"\x00");
            h.update(lock.as_bytes());
            format!("{:x}", h.finalize())
        }
        assert_ne!(
            compute_install_hash("pkg", "lock"),
            v1_hash("pkg", "lock"),
            "v2 must not collide with v1 — that's the whole point of the schema tag"
        );
    }

    #[test]
    fn workspace_root_detected() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        assert!(is_likely_workspace_root(dir.path()));
    }

    #[test]
    fn non_workspace_not_detected() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"a":"^1.0.0"}}"#,
        )
        .unwrap();
        assert!(!is_likely_workspace_root(dir.path()));
    }

    #[test]
    fn missing_package_json_not_workspace() {
        let dir = TempDir::new().unwrap();
        assert!(!is_likely_workspace_root(dir.path()));
    }

    #[test]
    fn missing_install_hash_returns_false() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        // No .lpm/install-hash
        let state = check_install_state(p);
        assert!(!state.up_to_date);
        assert!(state.hash.is_some());
    }

    // ── v2 mtime-fast-path tests ─────────────────────────

    fn setup_up_to_date_project_v2() -> TempDir {
        // Like `setup_up_to_date_project` but writes the install-hash
        // in v2 format (hash + mtime line) via `write_install_hash`.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let hash = compute_install_hash(
            &fs::read_to_string(p.join("package.json")).unwrap(),
            "lock-content",
        );
        write_install_hash(p, &hash, lpm_linker::LinkerMode::Isolated).unwrap();
        dir
    }

    #[test]
    fn v2_fast_path_returns_up_to_date_on_matching_mtimes() {
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());
        let state = check_install_state(dir.path());
        assert!(state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_binary_lockfile_keeps_install_from_fast_lane_success() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let package_json =
            r#"{"name":"lockb-fast-lane-repro","version":"1.0.0","dependencies":{}}"#;
        fs::write(p.join("package.json"), package_json).unwrap();
        lpm_lockfile::Lockfile::default()
            .write_to_file(&p.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let lock = fs::read_to_string(p.join(lpm_lockfile::LOCKFILE_NAME)).unwrap();
        let hash =
            compute_install_hash_v6(package_json, &lock, &[], lpm_linker::LinkerMode::Isolated);
        write_install_hash(p, &hash, lpm_linker::LinkerMode::Isolated).unwrap();

        let state = check_install_state(p);

        assert!(
            !state.up_to_date,
            "bare install must not exit before regenerating a representable missing lpm.lockb"
        );
    }

    #[test]
    fn v2_fast_path_rejects_when_pkg_mtime_changes() {
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());
        // Sleep briefly to cross the mtime resolution boundary, then
        // rewrite package.json identically — content-equal but new mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"a":"^1.0.0"}}"#,
        )
        .unwrap();
        let state = check_install_state(dir.path());
        // Fast path rejects → falls through to hash path, which passes
        // (content is identical). End-to-end still says up-to-date, but
        // via the slow path this time.
        assert!(state.up_to_date);
    }

    #[test]
    fn v2_fast_path_rejects_when_content_actually_changed() {
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());
        // Rewrite package.json with different content (mtime also changes).
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"b":"^2.0.0"}}"#,
        )
        .unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
    }

    #[test]
    fn v2_fast_path_rejects_on_external_node_modules_mutation() {
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());
        // Touch node_modules so its mtime is AFTER install-hash's mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.path().join("node_modules/.marker"), "").unwrap();
        let state = check_install_state(dir.path());
        assert!(
            !state.up_to_date,
            "external mutation under node_modules must invalidate fast path"
        );
    }

    #[test]
    fn v1_bare_hash_file_still_accepted_via_slow_path() {
        // Forward-compat: a v1 install-hash file (bare 64-char hex,
        // no mtime line) must still work — the fast path returns None
        // and the slow path reads + hashes as before.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(
            &fs::read_to_string(p.join("package.json")).unwrap(),
            "lock-content",
        );
        // Bare write — v1 format only.
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();
        let state = check_install_state(p);
        assert!(state.up_to_date);
    }

    #[test]
    fn write_install_hash_produces_v6_format() {
        // Contract: file content is hash + mtime line + linker line.
        // Pins the on-disk format so a v1 reader still gets the hash on
        // line 1 (legacy compat), AND the v6 mtime fast-path can detect
        // a post-install linker flip without recomputing the full hash.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        write_install_hash(p, "abc123", lpm_linker::LinkerMode::Hoisted).unwrap();
        let content = fs::read_to_string(p.join(".lpm").join("install-hash")).unwrap();
        let mut lines = content.lines();
        assert_eq!(lines.next().unwrap(), "abc123");
        let mtime_line = lines.next().unwrap();
        assert!(
            mtime_line.starts_with("m:"),
            "expected mtime line, got {mtime_line:?}"
        );
        let rest = mtime_line.strip_prefix("m:").unwrap();
        let parts: Vec<&str> = rest.split(':').collect();
        assert_eq!(parts.len(), 2, "mtime line must have two fields");
        assert!(parts[0].parse::<u64>().is_ok(), "pkg mtime must be u64");
        assert!(parts[1].parse::<u64>().is_ok(), "lock mtime must be u64");
        let linker_line = lines.next().unwrap();
        assert_eq!(
            linker_line, "l:hoisted",
            "expected linker line `l:hoisted`, got {linker_line:?}"
        );
    }

    /// `install-hash` is the freshness short-circuit `lpm dev` and the
    /// install fast lane consult. On shared hosts a default-umask
    /// (0o644) write lets any local uid forge or truncate it.
    /// The Unix create path must land at 0o600.
    #[cfg(unix)]
    #[test]
    fn install_hash_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        write_install_hash(p, "abc123", lpm_linker::LinkerMode::Hoisted).unwrap();
        let mode = fs::metadata(p.join(".lpm").join("install-hash"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            ".lpm/install-hash must be 0o600 on Unix, got {:#o}",
            mode
        );
    }

    /// Bug-fix idempotency: a second `write_install_hash` call must
    /// also leave the file at 0o600 — even if a prior actor
    /// (re-installed by another tool, manually edited) chmodded
    /// the file to 0o644. Atomic rename of a freshly-opened 0o600
    /// tmp file guarantees the destination perms regardless of the
    /// prior state.
    #[cfg(unix)]
    #[test]
    fn install_hash_rewrite_resets_perms_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        write_install_hash(p, "first", lpm_linker::LinkerMode::Hoisted).unwrap();
        let path = p.join(".lpm").join("install-hash");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_install_hash(p, "second", lpm_linker::LinkerMode::Hoisted).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewrite must restore 0o600, got {:#o}", mode);
    }

    #[test]
    fn linker_mode_folds_into_install_hash() {
        // v6 contract: switching linker mode must produce a different
        // hash for the same manifest + lockfile. Pre-v6 the hash only
        // keyed off content, so a post-install env/config flip left
        // the hash matching and the up-to-date fast-exit fired.
        let isolated =
            compute_install_hash_v6("pkg", "lock", &[], lpm_linker::LinkerMode::Isolated);
        let hoisted = compute_install_hash_v6("pkg", "lock", &[], lpm_linker::LinkerMode::Hoisted);
        assert_ne!(
            isolated, hoisted,
            "v6 must distinguish linker modes — otherwise the freshness \
             cache stays warm across `LPM_LINKER` flips and silently \
             leaves the project on the prior layout."
        );
    }

    #[test]
    fn mtime_fast_path_bails_when_stored_linker_differs() {
        // Pin: an install-hash file whose stored linker line says
        // `l:isolated` must NOT short-circuit a freshness check that
        // resolves to `hoisted`. Without this guard, a user setting
        // `LPM_LINKER=hoisted` after a successful isolated install
        // would see "up to date" until they touched a manifest.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        // Write the install-hash for an isolated layout.
        write_install_hash(p, "deadbeef", lpm_linker::LinkerMode::Isolated).unwrap();
        // Mtime fast path with matching linker → up_to_date.
        let pkg_content = fs::read_to_string(p.join("package.json")).unwrap();
        let same = try_mtime_fast_path(p, &pkg_content, lpm_linker::LinkerMode::Isolated);
        assert!(
            same.is_some_and(|s| s.up_to_date),
            "matching linker should keep up_to_date=true on the fast path"
        );
        // Mtime fast path with FLIPPED linker → bails (returns None).
        let flipped = try_mtime_fast_path(p, &pkg_content, lpm_linker::LinkerMode::Hoisted);
        assert!(
            flipped.is_none(),
            "stored linker `isolated` must NOT short-circuit a check \
             resolving to `hoisted` — the freshness gate is the load-\
             bearing seam for env/config-driven layout flips"
        );
    }

    #[test]
    fn check_install_state_with_content_returns_not_up_to_date_on_invalid_lpm_linker() {
        // Pin: even when the cache is warm and would otherwise match,
        // a syntactically invalid `LPM_LINKER` MUST surface as
        // `up_to_date = false` so the trailing install pipeline can
        // emit the parse error. Pre-fix the helper fell back to
        // `LinkerMode::Isolated` and silently produced `up_to_date =
        // true` — letting the bare `lpm install` sync fast lane and
        // `lpm dev`'s `needs_install` helper short-circuit on
        // misconfigured environments.
        let _env = crate::test_env::ScopedEnv::set([("LPM_LINKER", "symlink".into())]);

        let dir = setup_up_to_date_project_v2();
        let pkg_content = fs::read_to_string(dir.path().join("package.json")).unwrap();
        let state = check_install_state_with_content(dir.path(), &pkg_content);

        assert!(
            !state.up_to_date,
            "warm cache must NOT short-circuit when LPM_LINKER is invalid \
             — the trailing install pipeline is the fail-loud seam"
        );
        // `dev.rs::needs_install` reads `state.hash`; `None` means "no
        // package.json" and skips install. The placeholder hash forces
        // an install attempt instead, which surfaces the parse error.
        assert!(
            state.hash.is_some(),
            "hash must be Some(_) so dev / sync-fast-lane callers \
             trigger install — None signals 'no package.json' and \
             would silently mask the misconfigured env"
        );
    }

    #[test]
    fn check_install_state_returns_not_up_to_date_on_invalid_lpm_linker() {
        // Sibling pin for the entry point that does its own pkg.json
        // read. Same contract as the `_with_content` variant above.
        let _env = crate::test_env::ScopedEnv::set([("LPM_LINKER", "symlink".into())]);

        let dir = setup_up_to_date_project_v2();
        let state = check_install_state(dir.path());

        assert!(
            !state.up_to_date,
            "warm cache must NOT short-circuit through `check_install_state` \
             when LPM_LINKER is invalid"
        );
        assert!(state.hash.is_some());
    }

    #[test]
    fn check_install_state_with_content_skips_pkg_read() {
        // Contract: the fast-lane variant must behave identically to
        // `check_install_state` when given the correct content.
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());
        let content = fs::read_to_string(dir.path().join("package.json")).unwrap();
        let state = check_install_state_with_content(dir.path(), &content);
        assert!(state.up_to_date);
    }

    #[test]
    fn is_workspace_root_content_detects_workspace_key() {
        assert!(is_workspace_root_content(
            r#"{"name":"root","workspaces":["packages/*"]}"#
        ));
        assert!(!is_workspace_root_content(r#"{"name":"leaf"}"#));
    }

    // ── day-3 (F7a): file/link manifest folding ────────────

    fn make_dir_dep(parent: &Path, name: &str, version: &str) -> std::path::PathBuf {
        let dir = parent.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
        dir
    }

    #[test]
    fn collect_file_link_manifest_bytes_empty_for_no_local_deps() {
        // Project with only registry deps produces an empty manifest
        // bytes buffer — preserves the v2 hash semantic (post-tag-bump).
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"dependencies":{"lodash":"^4.0.0"}}"#;
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        assert!(bytes.is_empty());
    }

    #[test]
    fn collect_file_link_manifest_bytes_picks_up_file_directory_dep() {
        // Single file: directory dep → its package.json content
        // appears in the buffer.
        let dir = TempDir::new().unwrap();
        let _ = make_dir_dep(dir.path(), "local-dep", "1.0.0");
        let pkg = r#"{"dependencies":{"local-dep":"file:./local-dep"}}"#;
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        assert!(!bytes.is_empty());
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("local-dep"));
        assert!(s.contains("1.0.0"));
    }

    #[test]
    fn collect_file_link_manifest_bytes_picks_up_link_directory_dep() {
        // Same shape for `link:` (day-4 will materialize it; day-3
        // F7a already invalidates correctly when it appears).
        let dir = TempDir::new().unwrap();
        let _ = make_dir_dep(dir.path(), "linked", "0.5.0");
        let pkg = r#"{"dependencies":{"linked":"link:./linked"}}"#;
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("linked"));
        assert!(s.contains("0.5.0"));
    }

    #[test]
    fn collect_file_link_manifest_bytes_skips_file_tarball() {
        // A `file:./foo.tgz` (regular file, not a directory) is
        // content-integrity-locked elsewhere; F7a explicitly excludes
        // it from the up-to-date freshness signal.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("foo.tgz"), b"fake tarball bytes").unwrap();
        let pkg = r#"{"dependencies":{"foo":"file:./foo.tgz"}}"#;
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        assert!(bytes.is_empty(), "file: tarball must not contribute to F7a");
    }

    #[test]
    fn collect_file_link_manifest_bytes_recurses_into_transitive_local_deps() {
        // A → B (file:); B → C (file:). Both B and C's package.json
        // appear in the buffer.
        let dir = TempDir::new().unwrap();
        let b = make_dir_dep(dir.path(), "B", "1.0.0");
        let _ = make_dir_dep(&b, "C", "2.0.0");
        // Rewrite B's package.json so it declares C as a file: dep.
        fs::write(
            b.join("package.json"),
            r#"{"name":"B","version":"1.0.0","dependencies":{"C":"file:./C"}}"#,
        )
        .unwrap();
        let pkg = r#"{"dependencies":{"B":"file:./B"}}"#;
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("\"name\":\"B\""), "B's manifest must appear");
        assert!(s.contains("\"name\":\"C\""), "C's manifest must appear");
    }

    #[test]
    fn collect_file_link_manifest_bytes_realpath_cycle_detect() {
        // A → B (file:); B → A (file:). Realpath dedupe stops the
        // recursion; the function returns without infinite-looping.
        let dir = TempDir::new().unwrap();
        let a = make_dir_dep(dir.path(), "A", "1.0.0");
        let b = make_dir_dep(dir.path(), "B", "1.0.0");
        fs::write(
            a.join("package.json"),
            r#"{"name":"A","version":"1.0.0","dependencies":{"B":"file:../B"}}"#,
        )
        .unwrap();
        fs::write(
            b.join("package.json"),
            r#"{"name":"B","version":"1.0.0","dependencies":{"A":"file:../A"}}"#,
        )
        .unwrap();
        let pkg = r#"{"dependencies":{"A":"file:./A"}}"#;
        // If cycle-detect is broken, this hangs forever or stack-
        // overflows. Test passes if it returns within a reasonable
        // time budget (test harness's ~60s default).
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        let s = String::from_utf8_lossy(&bytes);
        // Both A and B appear exactly once.
        assert_eq!(s.matches("\"name\":\"A\"").count(), 1);
        assert_eq!(s.matches("\"name\":\"B\"").count(), 1);
    }

    #[test]
    fn collect_file_link_manifest_bytes_depth_bound_at_3() {
        // A → B → C → D. Depth bound is 3 levels deep relative to the
        // consumer, so the consumer's pkg.json (depth 0) processes A
        // (depth 0 walking adds A's manifest to buf and recurses
        // walk(depth=1)), A's deps (depth 1) processes B, B's deps
        // (depth 2) processes C, C's deps (depth 3) — at depth==3
        // walk returns immediately without processing D. Net: A, B, C
        // appear; D does not.
        let dir = TempDir::new().unwrap();
        let a = make_dir_dep(dir.path(), "A", "1.0.0");
        let b = make_dir_dep(&a, "B", "1.0.0");
        let c = make_dir_dep(&b, "C", "1.0.0");
        let _d = make_dir_dep(&c, "D", "1.0.0");
        fs::write(
            a.join("package.json"),
            r#"{"name":"A","version":"1.0.0","dependencies":{"B":"file:./B"}}"#,
        )
        .unwrap();
        fs::write(
            b.join("package.json"),
            r#"{"name":"B","version":"1.0.0","dependencies":{"C":"file:./C"}}"#,
        )
        .unwrap();
        fs::write(
            c.join("package.json"),
            r#"{"name":"C","version":"1.0.0","dependencies":{"D":"file:./D"}}"#,
        )
        .unwrap();
        let pkg = r#"{"dependencies":{"A":"file:./A"}}"#;
        let bytes = collect_file_link_manifest_bytes(dir.path(), pkg);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("\"name\":\"A\""));
        assert!(s.contains("\"name\":\"B\""));
        assert!(s.contains("\"name\":\"C\""));
        assert!(
            !s.contains("\"name\":\"D\""),
            "depth bound must exclude D (depth 4)",
        );
    }

    #[test]
    fn collect_file_link_manifest_bytes_deterministic_across_runs() {
        // Same project state → same bytes. This is what install-hash
        // determinism depends on. The HashSet iteration order in the
        // walk could break this if `buf` weren't sorted at the end.
        let dir = TempDir::new().unwrap();
        let _ = make_dir_dep(dir.path(), "alpha", "1.0.0");
        let _ = make_dir_dep(dir.path(), "beta", "1.0.0");
        let pkg = r#"{"dependencies":{"alpha":"file:./alpha","beta":"file:./beta"}}"#;

        let b1 = collect_file_link_manifest_bytes(dir.path(), pkg);
        let b2 = collect_file_link_manifest_bytes(dir.path(), pkg);
        assert_eq!(b1, b2, "F7a output must be deterministic");
        assert!(!b1.is_empty());
    }

    #[test]
    fn install_hash_invalidates_on_file_dep_pkg_json_edit() {
        // The point of F7a: editing a local source's package.json
        // changes the install-hash, so the up-to-date check returns
        // `false` and the install runs.
        let dir = TempDir::new().unwrap();
        let local = make_dir_dep(dir.path(), "local", "1.0.0");
        let pkg = r#"{"dependencies":{"local":"file:./local"}}"#;

        let bytes_before = collect_file_link_manifest_bytes(dir.path(), pkg);
        let hash_before = compute_install_hash_v3(pkg, "lock", &bytes_before);

        // Edit the source's package.json (bump version, add a dep, etc.).
        fs::write(
            local.join("package.json"),
            r#"{"name":"local","version":"2.0.0"}"#,
        )
        .unwrap();

        let bytes_after = collect_file_link_manifest_bytes(dir.path(), pkg);
        let hash_after = compute_install_hash_v3(pkg, "lock", &bytes_after);

        assert_ne!(
            hash_before, hash_after,
            "F7a contract: editing a file: dep's package.json must invalidate the install hash",
        );
    }

    #[test]
    fn check_install_state_invalidates_after_file_dep_pkg_json_edit() {
        // End-to-end through `check_install_state` (the install-time
        // entry point): a project that's "up-to-date", then a local-
        // dep edit, then re-check → no longer up-to-date.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let local = make_dir_dep(p, "local", "1.0.0");
        let pkg = r#"{"dependencies":{"local":"file:./local"}}"#;
        fs::write(p.join("package.json"), pkg).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();

        // Compute and write the v3 hash AS THE INSTALL PIPELINE
        // WOULD (with file/link bytes folded in).
        let bytes = collect_file_link_manifest_bytes(p, pkg);
        let initial_hash = compute_install_hash_v3(pkg, "lock-content", &bytes);
        write_install_hash(p, &initial_hash, lpm_linker::LinkerMode::Isolated).unwrap();
        let _home = scoped_home_for(p);

        // Sanity: up-to-date right after install.
        assert!(check_install_state(p).up_to_date);

        // Sleep to cross mtime resolution boundary, then edit the
        // local source's manifest. Note the consumer's package.json
        // and lpm.lock are unchanged; only the file: dep changed.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            local.join("package.json"),
            r#"{"name":"local","version":"2.0.0"}"#,
        )
        .unwrap();

        let state_after = check_install_state(p);
        assert!(
            !state_after.up_to_date,
            "F7a contract: edits to a file: dep's package.json must surface as needs-install",
        );
    }

    // ── audit response (round 6) — workspace-member manifest folding ──

    /// Round-6 contract: a workspace member's package.json is folded
    /// into the install-hash even when the root manifest doesn't
    /// reference it via `file:` / `link:`. Pre-fix, an edit to a
    /// member's manifest left the install-hash unchanged and the
    /// next install hit the "up to date" fast-exit, missing the new
    /// transitive `workspace:` ref the round-5 BFS would have
    /// expanded.
    #[test]
    fn collect_file_link_manifest_bytes_includes_workspace_members_round6() {
        let dir = TempDir::new().unwrap();
        // Workspace root with two members. Root deps are empty —
        // pre-fix, this means `walk_file_link_deps` produces an empty
        // buffer because the root has no file:/link:.
        let root_pkg = r#"{"name":"root","workspaces":["packages/*"]}"#;
        fs::write(dir.path().join("package.json"), root_pkg).unwrap();
        fs::create_dir_all(dir.path().join("packages/foo")).unwrap();
        fs::write(
            dir.path().join("packages/foo/package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/bar")).unwrap();
        fs::write(
            dir.path().join("packages/bar/package.json"),
            r#"{"name":"bar","version":"1.0.0"}"#,
        )
        .unwrap();

        let bytes_initial = collect_file_link_manifest_bytes(dir.path(), root_pkg);
        assert!(
            !bytes_initial.is_empty(),
            "round-6 fix: workspace member manifests must contribute to the install-hash buffer \
             even when no file:/link: dep is declared at the root",
        );
        // Both members must be referenced (their manifest contents
        // are folded in).
        let s = String::from_utf8_lossy(&bytes_initial).to_string();
        assert!(
            s.contains("\"foo\""),
            "foo's manifest content must be in buffer: {s}"
        );
        assert!(
            s.contains("\"bar\""),
            "bar's manifest content must be in buffer: {s}"
        );

        // Edit foo's manifest to add a transitive `workspace:` dep.
        // This is the auditor's HIGH 1 repro at the unit level —
        // the buffer must change so the install-hash invalidates.
        fs::write(
            dir.path().join("packages/foo/package.json"),
            r#"{"name":"foo","version":"1.0.0","dependencies":{"bar":"workspace:*"}}"#,
        )
        .unwrap();
        let bytes_after = collect_file_link_manifest_bytes(dir.path(), root_pkg);
        assert_ne!(
            bytes_initial, bytes_after,
            "round-6 fix: editing a workspace member's package.json must change the manifest \
             buffer so the install-hash invalidates",
        );
    }

    /// Round-6: when a member is ALSO referenced via `file:` from the
    /// root, dedupe by realpath — don't fold the same member's
    /// manifest in twice. Different shape than the previous test;
    /// guards against accidental double-counting.
    #[test]
    fn collect_file_link_manifest_bytes_dedupes_workspace_member_against_file_dep() {
        let dir = TempDir::new().unwrap();
        let root_pkg = r#"{"name":"root","workspaces":["packages/*"],"dependencies":{"foo":"file:./packages/foo"}}"#;
        fs::write(dir.path().join("package.json"), root_pkg).unwrap();
        fs::create_dir_all(dir.path().join("packages/foo")).unwrap();
        fs::write(
            dir.path().join("packages/foo/package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();

        let bytes = collect_file_link_manifest_bytes(dir.path(), root_pkg);
        let s = String::from_utf8_lossy(&bytes).to_string();
        // Foo must appear ONCE — once as file:, then deduped on the
        // workspace pass.
        let occurrences = s.matches(r#""name":"foo""#).count();
        assert_eq!(
            occurrences, 1,
            "workspace-member dedupe: foo's manifest must be in the buffer exactly once, \
             got {occurrences}: {s}",
        );
    }

    // ── D8c — layout-aware freshness gate ─────────────────
    //
    // These tests pin the contract that an upgrade-in-place user
    // (binary upgraded but `node_modules/` not wiped) does NOT
    // short-circuit the fast lane, regardless of which exit path the
    // up-to-date check takes (full-read or mtime fast path).

    #[test]
    fn legacy_layout_present_forces_install_via_full_read() {
        // Setup: an otherwise-up-to-date project that ALSO has the
        // legacy wrapper layout populated under node_modules/.lpm/.
        // The migration gate must fire and force `up_to_date = false`.
        let dir = setup_up_to_date_project();
        let p = dir.path();
        let _home = scoped_home_for(p);
        // Populate legacy wrapper root — this is what an
        // upgrade-in-place user's project looks like.
        fs::create_dir_all(p.join("node_modules/.lpm/express@4.22.1")).unwrap();
        let state = check_install_state(p);
        assert!(
            !state.up_to_date,
            "legacy layout populated must force install regardless of hash match"
        );
        assert!(state.hash.is_some());
    }

    #[test]
    fn legacy_layout_present_forces_install_via_mtime_fast_path() {
        // Same setup as above but with the v2 mtime line written so
        // `try_mtime_fast_path` would normally short-circuit. The
        // 61.3 gate inside try_mtime_fast_path returns None,
        // forcing fall-through to the slow path which then ALSO
        // bails via the migration gate.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg_json = r#"{"dependencies":{"a":"^1.0.0"}}"#;
        let lock = "lock-content";
        fs::write(p.join("package.json"), pkg_json).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(pkg_json, lock);
        // Use the real writer so the v6 mtime + linker lines are captured.
        write_install_hash(p, &hash, lpm_linker::LinkerMode::Isolated).unwrap();
        // Populate legacy layout AFTER write_install_hash so the
        // mtime check on node_modules vs hash file isn't the thing
        // that bails (we want the migration gate to be the bailing
        // signal). Re-touch hash file mtime forward so the
        // node-modules-newer-than-hash path doesn't fire either.
        fs::create_dir_all(p.join("node_modules/.lpm/express@4.22.1")).unwrap();

        let state = check_install_state(p);
        assert!(
            !state.up_to_date,
            "mtime fast path must bail when legacy layout is populated"
        );
    }

    #[test]
    fn empty_legacy_dir_does_not_force_install() {
        // An empty `node_modules/.lpm/` (e.g., from a partial wipe
        // or an initial cleanup_stale_entries call) is NOT
        // sufficient evidence of a legacy install. The gate only
        // fires when the legacy root is non-empty.
        //
        // Test layout: pre-create the empty `.lpm/` BEFORE the
        // setup helper writes the hash so `node_modules` mtime ≤
        // hash mtime; otherwise the standard external-modification
        // check trips first and we never reach the migration gate.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg_json = r#"{"dependencies":{"a":"^1.0.0"}}"#;
        fs::write(p.join("package.json"), pkg_json).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        // Empty `.lpm/` dir created before hash write.
        fs::create_dir_all(p.join("node_modules/.lpm")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(pkg_json, "lock-content");
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();

        let state = check_install_state(p);
        assert!(state.up_to_date, "empty legacy dir must not gate install");
    }

    /// D8c contract — historically asserted that "both
    /// legacy + new isolated wrapper layouts populated → migration
    /// complete → up-to-date".  the default flip to
    /// v2 changes this: `<project>/.lpm/wrappers/` is now the
    /// LEGACY-V1 marker and triggers a v2 migration regardless of
    /// the legacy isolated-vs-new-isolated distinction. The 4d gate
    /// fires unconditionally on v1 wrappers when the active store
    /// version is v2, and `StoreVersion::default()` is v2 since the
    /// flip — so this test now asserts the post-contract:
    /// v1 wrappers populated → v2 migration owed → up-to-date is
    /// false. The pre-"both isolated layouts populated →
    /// fresh" contract is intentionally retired.
    #[test]
    fn populated_v1_wrappers_force_v2_migration_on_default() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg_json = r#"{"dependencies":{"a":"^1.0.0"}}"#;
        fs::write(p.join("package.json"), pkg_json).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm/wrappers/express@4.22.1")).unwrap();
        let hash = compute_install_hash(pkg_json, "lock-content");
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();

        let state = check_install_state(p);
        assert!(
            !state.up_to_date,
            "v1 wrappers under post-4d v2 default must trigger migration"
        );
    }
}
