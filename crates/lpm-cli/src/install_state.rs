//! Sync-safe install-state check shared by the top-of-main fast lane,
//! `install.rs`, and `dev.rs`. Single source of truth — never duplicate.
//!
//! extracted from `install.rs::is_install_up_to_date()`
//! and `dev.rs::compute_install_hash()` / `dev.rs::needs_install()`.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::UNIX_EPOCH;

use lpm_store::SecurityAnalysisPolicy;
use lpm_store::v2::{ObjectIntegrityPolicy, PlatformTuple};

/// Atomically publish rebuildable install state with owner-only Unix permissions.
/// Missing or invalid state requires validation again; recovery records retain
/// their separate durability guarantees.
fn write_state_file_owner_only(path: &Path, content: &[u8]) -> std::io::Result<()> {
    lpm_common::write_file_atomic_with_options(
        path,
        content,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
}

pub(crate) fn is_node_runtime_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn refresh_install_hash_node_runtime_fingerprint(
    project_dir: &Path,
    expected_dependency_engine_key: &str,
    runtime_fingerprint: Option<&str>,
) -> std::io::Result<bool> {
    if runtime_fingerprint.is_some_and(|value| !is_node_runtime_fingerprint(value)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Node runtime fingerprint",
        ));
    }

    let path = project_dir.join(".lpm").join("install-hash");
    let original = lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(std::io::Error::other)?;
    let Some(updated) = replace_node_runtime_fingerprint(
        &original,
        expected_dependency_engine_key,
        runtime_fingerprint,
    ) else {
        return Ok(false);
    };
    if updated == original {
        return Ok(false);
    }

    if lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(std::io::Error::other)?
        != original
    {
        return Ok(false);
    }
    write_state_file_owner_only(&path, updated.as_bytes())?;
    Ok(true)
}

fn replace_node_runtime_fingerprint(
    content: &str,
    expected_dependency_engine_key: &str,
    runtime_fingerprint: Option<&str>,
) -> Option<String> {
    let mut updated = String::with_capacity(content.len() + 72);
    let mut saw_engine_key = false;
    let mut saw_runtime_fingerprint = false;
    let fingerprint = runtime_fingerprint.unwrap_or("none");

    for line in content.lines() {
        if let Some(key) = line.strip_prefix("e:") {
            if saw_engine_key || key != expected_dependency_engine_key {
                return None;
            }
            saw_engine_key = true;
        }

        if line.starts_with("n:") {
            if saw_runtime_fingerprint {
                return None;
            }
            saw_runtime_fingerprint = true;
            updated.push_str("n:");
            updated.push_str(fingerprint);
        } else {
            updated.push_str(line);
        }
        updated.push('\n');
    }

    if !saw_engine_key {
        return None;
    }
    if !saw_runtime_fingerprint {
        updated.push_str("n:");
        updated.push_str(fingerprint);
        updated.push('\n');
    }
    Some(updated)
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
/// - `v2`: resolved `devDependencies` also participate in install freshness.
/// - `v3`: file:/link: directory dependency manifests participate in freshness.
/// - `v4`: root link targets participate in freshness.
/// - `v5`: workspace member manifests participate in freshness.
/// - `v6`: resolved linker mode participates in freshness.
/// - `v7`: v2 object integrity policy participates in freshness.
/// - `v8`: host platform tuple participates in freshness.
/// - `v9`: dependency-engine policy participates when the lockfile contains
///   dependency `engines.node` constraints. Unconstrained projects retain
///   their v8 hash so the common path does not churn install state.
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
//
// **v7 — v2 object integrity policy folds into the hash.** Pre-v7,
// switching from `source` to `tree` integrity could leave a warm bare
// install exiting before reusable v2 objects were checked with the
// stricter tree policy. v7 also adds an `i:<source|tree>` install-hash
// line so the mtime fast path detects the same flip without rehashing.
//
// **v8 — host platform tuple folds into the hash.** Pre-v8, a project
// cache moved between OS/CPU/libc environments could fast-exit before
// platform-specific optional dependency filtering ran. v8 also adds a
// `p:<os>/<cpu>/<libc>` install-hash line so the mtime fast path detects
// the same host change without recomputing the full hash.
//
// **v9 — dependency-engine context folds into constrained hashes.** A
// lockfile containing dependency `engines.node` constraints is interpreted
// against both engine strictness and the effective Node version. v9 layers
// that context over the v8 base hash and records an `e:<key>` line so both
// the full and mtime freshness paths rerun when either value changes. The
// `none` key returns the v8 hash to preserve warm state for unconstrained
// projects.
const INSTALL_HASH_SCHEMA_TAG: &[u8] = b"lpm-install-hash-v8\x00";

/// Compute the install hash from raw file contents — back-compat shim
/// that defaults file/link bytes to empty AND linker mode to the
/// active default. Used by test fixtures and `dev.rs`'s
/// deterministic-hash unit tests where the linker is not under test.
/// Production callers use [`compute_install_hash_v8`] directly.
///
/// flipped [`LinkerMode::default`] from Isolated to
/// Hoisted; this shim follows the flip so callers expecting "the hash
/// for a default install" get the post-4f shape.
pub fn compute_install_hash(pkg_content: &str, lock_content: &str) -> String {
    compute_install_hash_v10(
        pkg_content,
        lock_content,
        &[],
        lpm_linker::LinkerMode::default(),
        ObjectIntegrityPolicy::Source,
        &PlatformTuple::current(),
        InstallHashContext::default(),
    )
}

/// Same shape as [`compute_install_hash_v8`] minus the linker and
/// integrity-policy args —
/// retained ONLY to keep the v3 name available to callers that
/// explicitly want the active default. Behaves identically to
/// `compute_install_hash_v8(..., LinkerMode::default(),
/// ObjectIntegrityPolicy::Source, PlatformTuple::current())`. New code
/// should call `compute_install_hash_v8` and pass the resolved mode,
/// policy, and platform tuple.
pub fn compute_install_hash_v3(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
) -> String {
    compute_install_hash_v10(
        pkg_content,
        lock_content,
        file_link_manifests,
        lpm_linker::LinkerMode::default(),
        ObjectIntegrityPolicy::Source,
        &PlatformTuple::current(),
        InstallHashContext::default(),
    )
}

/// Back-compat shim for callers that only key on the linker dimension.
/// New production code should call [`compute_install_hash_v8`] and pass
/// the resolved object integrity policy and platform tuple.
pub fn compute_install_hash_v6(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
    linker_mode: lpm_linker::LinkerMode,
) -> String {
    compute_install_hash_v10(
        pkg_content,
        lock_content,
        file_link_manifests,
        linker_mode,
        ObjectIntegrityPolicy::Source,
        &PlatformTuple::current(),
        InstallHashContext::default(),
    )
}

/// Back-compat shim for callers that pass the resolved linker and object
/// integrity policy but not an explicit platform tuple.
pub fn compute_install_hash_v7(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
) -> String {
    compute_install_hash_v10(
        pkg_content,
        lock_content,
        file_link_manifests,
        linker_mode,
        object_integrity_policy,
        &PlatformTuple::current(),
        InstallHashContext::default(),
    )
}

/// Full install hash with manifest content + lockfile + file/link
/// manifests + resolved linker mode + resolved v2 object integrity
/// policy + current host platform tuple folded in.
///
/// Including linker in the hash closes the post-install env/config
/// freshness gap: if a user runs `lpm install` once with the default
/// isolated layout and then sets `LPM_LINKER=hoisted`, pre-v6 the hash
/// stayed the same and the "up to date" fast-exit fired — leaving
/// the project on isolated despite the requested switch. v6 keys the
/// hash on the resolved linker so any flip invalidates the cache.
/// Including integrity policy does the same for `source` ↔ `tree`
/// switches. Including the platform tuple forces a re-run when a cached
/// project moves between OS/CPU/libc environments.
///
/// `pkg_content` and each manifest in `file_link_manifests` count as
/// [`manifest_for_install_hash`] reads them, so editing a script no install
/// step runs leaves the hash unchanged.
///
/// Order discipline: `schema_tag || pkg || \0 || lock || \0 || flb ||
/// \0 || linker || \0 || integrity_policy || \0 || platform`. Each
/// section is separated by an explicit `\0` domain separator so a future
/// caller can't construct an ambiguous input.
/// The linker byte is the canonical string from [`LinkerMode::as_str`]
/// (`"isolated"` or `"hoisted"`).
pub fn compute_install_hash_v8(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INSTALL_HASH_SCHEMA_TAG);
    hasher.update(manifest_for_install_hash(pkg_content.as_bytes()));
    hasher.update(b"\x00"); // domain separator prevents "ab"+"cd" == "abc"+"d"
    hasher.update(lock_content.as_bytes());
    hasher.update(b"\x00");
    hasher.update(file_link_manifests);
    hasher.update(b"\x00");
    hasher.update(linker_mode.as_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(object_integrity_policy.as_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(platform_tuple_key(platform).as_bytes());
    hex::encode(hasher.finalize())
}

pub fn compute_install_hash_v9(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    dependency_engine_key: &str,
) -> String {
    let base = compute_install_hash_v8(
        pkg_content,
        lock_content,
        file_link_manifests,
        linker_mode,
        object_integrity_policy,
        platform,
    );
    if dependency_engine_key == "none" {
        return base;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"lpm-install-hash-v9-dependency-engines\x00");
    hasher.update(base.as_bytes());
    hasher.update(b"\x00");
    hasher.update(dependency_engine_key.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct InstallHashContext<'a> {
    pub(crate) dependency_engine_key: &'a str,
    pub(crate) security_analysis_policy: SecurityAnalysisPolicy,
}

impl Default for InstallHashContext<'static> {
    fn default() -> Self {
        Self {
            dependency_engine_key: "none",
            security_analysis_policy:
                crate::source_analysis_config::DEFAULT_SECURITY_ANALYSIS_POLICY,
        }
    }
}

pub(crate) fn compute_install_hash_v10(
    pkg_content: &str,
    lock_content: &str,
    file_link_manifests: &[u8],
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    context: InstallHashContext<'_>,
) -> String {
    let base = compute_install_hash_v9(
        pkg_content,
        lock_content,
        file_link_manifests,
        linker_mode,
        object_integrity_policy,
        platform,
        context.dependency_engine_key,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-install-hash-v10-source-analysis\0");
    hasher.update(base.as_bytes());
    hasher.update(b"\0");
    hasher.update(context.security_analysis_policy.as_str().as_bytes());
    hex::encode(hasher.finalize())
}

/// Whether an install step reads the script `name`: a lifecycle phase
/// `lpm install` runs for the project and its workspace members, or a
/// dependency phase its script policy blocks or runs for local packages.
fn install_reads_script(name: &str) -> bool {
    crate::commands::root_lifecycle::is_install_lifecycle_script(name)
        || lpm_security::SecurityPolicy::is_blocked_script(name)
}

/// `manifest` as install freshness reads it: its JSON value without the
/// `scripts` no install step reads, so editing a `dev` or `build` script,
/// or reformatting the file, leaves an install up to date. Anything that
/// isn't a JSON object, such as `pnpm-workspace.yaml`, is read as written.
fn manifest_for_install_hash(manifest: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let json = manifest.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(manifest);
    let Ok(serde_json::Value::Object(mut document)) = serde_json::from_slice(json) else {
        return std::borrow::Cow::Borrowed(manifest);
    };
    if let Some(serde_json::Value::Object(scripts)) = document.get_mut("scripts") {
        scripts.retain(|name, _| install_reads_script(name));
        if scripts.is_empty() {
            document.shift_remove("scripts");
        }
    }
    // The dependency-skills fingerprint covers `lpm.skills`; the dependency
    // pipeline never reads it.
    if let Some(serde_json::Value::Object(lpm)) = document.get_mut("lpm")
        && lpm.shift_remove("skills").is_some()
        && lpm.is_empty()
    {
        document.shift_remove("lpm");
    }
    match serde_json::to_vec(&document) {
        Ok(canonical) => std::borrow::Cow::Owned(canonical),
        Err(_) => std::borrow::Cow::Borrowed(manifest),
    }
}

fn platform_tuple_key(platform: &PlatformTuple) -> String {
    let libc = platform.libc.as_deref().unwrap_or("none");
    let mut key = String::with_capacity(platform.os.len() + platform.cpu.len() + libc.len() + 2);
    key.push_str(&platform.os);
    key.push('/');
    key.push_str(&platform.cpu);
    key.push('/');
    key.push_str(libc);
    key
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
pub(crate) enum FileLinkManifestBytes {
    Shared(std::sync::Arc<crate::workspace_discovery_cache::WorkspaceFreshnessSnapshot>),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for FileLinkManifestBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Shared(snapshot) => &snapshot.flattened,
            Self::Owned(bytes) => bytes,
        }
    }
}

impl FileLinkManifestBytes {
    fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Shared(snapshot) => snapshot.flattened.clone(),
            Self::Owned(bytes) => bytes,
        }
    }
}

#[inline]
fn may_contain_local_source_specifier(pkg_content: &str) -> bool {
    pkg_content.contains("file:") || pkg_content.contains("link:") || pkg_content.contains("\\u")
}

pub(crate) fn collect_file_link_manifest_bytes_shared(
    project_dir: &std::path::Path,
    pkg_content: &str,
) -> FileLinkManifestBytes {
    let mut buf: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
    if may_contain_local_source_specifier(pkg_content) {
        let mut visited: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        walk_file_link_deps(project_dir, pkg_content, 0, 3, &mut visited, &mut buf);
    }

    let workspace_snapshot =
        crate::workspace_discovery_cache::workspace_freshness_snapshot(project_dir, || {
            collect_workspace_freshness_snapshot(project_dir)
        });

    if buf.is_empty() {
        return FileLinkManifestBytes::Shared(workspace_snapshot);
    }

    let mut local_entries: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::with_capacity(buf.len());
    for (path, content) in buf {
        let normalized = manifest_for_install_hash(&content).into_owned();
        local_entries.push((path, normalized));
    }
    local_entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    local_entries.dedup_by(|left, right| left.0 == right.0);

    let ws_entries = &workspace_snapshot.entries;
    if local_entries.iter().all(|(path, content)| {
        ws_entries
            .binary_search_by(|(ws_path, _)| ws_path.cmp(path))
            .is_ok_and(|index| ws_entries[index].1 == *content)
    }) {
        return FileLinkManifestBytes::Shared(workspace_snapshot);
    }

    let local_capacity = local_entries.iter().fold(0usize, |total, (path, content)| {
        total
            .saturating_add(path.as_os_str().as_encoded_bytes().len())
            .saturating_add(content.len())
            .saturating_add(2)
    });
    let mut out = Vec::with_capacity(
        workspace_snapshot
            .flattened
            .len()
            .saturating_add(local_capacity),
    );
    let mut li = 0usize;
    let mut wi = 0usize;
    while li < local_entries.len() && wi < ws_entries.len() {
        match local_entries[li].0.cmp(&ws_entries[wi].0) {
            std::cmp::Ordering::Less => {
                append_manifest_wire_entry(&mut out, &local_entries[li].0, &local_entries[li].1);
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                append_manifest_wire_entry(&mut out, &ws_entries[wi].0, &ws_entries[wi].1);
                wi += 1;
            }
            std::cmp::Ordering::Equal => {
                append_manifest_wire_entry(&mut out, &local_entries[li].0, &local_entries[li].1);
                li += 1;
                wi += 1;
            }
        }
    }
    for (path, content) in &local_entries[li..] {
        append_manifest_wire_entry(&mut out, path, content);
    }
    for (path, content) in &ws_entries[wi..] {
        append_manifest_wire_entry(&mut out, path, content);
    }
    FileLinkManifestBytes::Owned(out)
}

#[inline]
fn append_manifest_wire_entry(out: &mut Vec<u8>, path: &std::path::Path, normalized: &[u8]) {
    out.extend_from_slice(path.to_string_lossy().as_bytes());
    out.push(0);
    out.extend_from_slice(normalized);
    out.push(0);
}

pub fn collect_file_link_manifest_bytes(
    project_dir: &std::path::Path,
    pkg_content: &str,
) -> Vec<u8> {
    collect_file_link_manifest_bytes_shared(project_dir, pkg_content).into_vec()
}

fn collect_workspace_freshness_snapshot(
    project_dir: &std::path::Path,
) -> crate::workspace_discovery_cache::WorkspaceFreshnessSnapshot {
    let mut freshness_files = std::collections::HashSet::new();
    let mut visited = std::collections::HashSet::new();
    let mut normalized_entries = Vec::new();
    let mut raw_local_deps = Vec::new();

    if let Some(path) = nearest_pnpm_workspace_yaml(project_dir) {
        push_freshness_file(path, &mut freshness_files, &mut normalized_entries);
    }

    let Ok(Some(workspace)) = crate::workspace_discovery_cache::discover_workspace(project_dir)
    else {
        return crate::workspace_discovery_cache::WorkspaceFreshnessSnapshot::from_normalized_entries(
            normalized_entries,
        );
    };
    push_freshness_file(
        workspace.root.join("pnpm-workspace.yaml"),
        &mut freshness_files,
        &mut normalized_entries,
    );
    push_freshness_file(
        workspace.root.join("package.json"),
        &mut freshness_files,
        &mut normalized_entries,
    );
    normalized_entries.reserve(workspace.members.len());
    for member in &workspace.members {
        let Ok(realpath) = member.path.canonicalize() else {
            continue;
        };
        if !visited.insert(realpath.clone()) {
            continue;
        }
        let Ok(member_content) = lpm_common::read_text_file_capped(
            &realpath.join("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) else {
            continue;
        };
        let normalized = manifest_for_install_hash(member_content.as_bytes()).into_owned();
        normalized_entries.push((realpath.clone(), normalized));
        if may_contain_local_source_specifier(&member_content) {
            walk_file_link_deps(
                &realpath,
                &member_content,
                0,
                3,
                &mut visited,
                &mut raw_local_deps,
            );
        }
    }
    for (path, raw_content) in raw_local_deps {
        let normalized = manifest_for_install_hash(&raw_content).into_owned();
        normalized_entries.push((path, normalized));
    }
    crate::workspace_discovery_cache::WorkspaceFreshnessSnapshot::from_normalized_entries(
        normalized_entries,
    )
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

/// Whether the nearest `pnpm-workspace.yaml` declares workspace
/// `packages`. pnpm also accepts the file holding only settings
/// (`allowBuilds`, catalogs, overrides), which declares no workspace. A
/// file that can't be read or parsed counts as declaring packages, so
/// workspace discovery reports the problem.
pub fn pnpm_workspace_declares_packages(project_dir: &std::path::Path) -> bool {
    let Some(path) = nearest_pnpm_workspace_yaml(project_dir) else {
        return false;
    };
    let Ok(content) =
        lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    else {
        return true;
    };
    match serde_yaml::from_str::<serde_yaml::Value>(lpm_common::strip_utf8_bom_str(&content)) {
        Ok(serde_yaml::Value::Null) => false,
        Ok(document) => document
            .get("packages")
            .is_some_and(|packages| packages.as_sequence().is_none_or(|list| !list.is_empty())),
        Err(_) => true,
    }
}

fn push_freshness_file(
    path: std::path::PathBuf,
    seen: &mut std::collections::HashSet<std::path::PathBuf>,
    buf: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
) {
    let Ok(content) = lpm_common::read_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    else {
        return;
    };
    let key = path.canonicalize().unwrap_or(path);
    if seen.insert(key.clone()) {
        buf.push((key, manifest_for_install_hash(&content).into_owned()));
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
    let Ok(pkg) =
        serde_json::from_str::<serde_json::Value>(lpm_common::strip_utf8_bom_str(pkg_content))
    else {
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
            let Ok(manifest_content) = lpm_common::read_text_file_capped(
                &realpath.join("package.json"),
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            ) else {
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
    let Ok(pkg_content) =
        lpm_common::read_text_file_capped(&pkg_json, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    else {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    };

    check_install_state_with_content(project_dir, &pkg_content)
}

/// Same semantics as [`check_install_state`] but accepts a pre-read
/// `package.json` content from the caller. Linker resolution still runs
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
    let object_integrity_policy =
        match crate::commands::config::resolve_object_integrity_policy(&cfg) {
            Ok(policy) => policy,
            Err(_) => return invalid_integrity_state(project_dir, pkg_content, linker_mode),
        };
    let security_analysis_policy =
        match crate::source_analysis_config::read_install_time_source_analysis(&cfg) {
            Ok(true) => SecurityAnalysisPolicy::Enabled,
            Ok(false) => SecurityAnalysisPolicy::Disabled,
            Err(_) => return invalid_integrity_state(project_dir, pkg_content, linker_mode),
        };
    check_install_state_with_linker_integrity_dependency_engine_and_security_analysis(
        project_dir,
        pkg_content,
        linker_mode,
        object_integrity_policy,
        "none",
        lpm_store::StoreVersion::from_env(),
        security_analysis_policy,
    )
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
    let lock_content =
        crate::commands::install::workspace_lockfile::active_lockfile_content(project_dir);
    let file_link_bytes = collect_file_link_manifest_bytes_shared(project_dir, pkg_content);
    let platform = PlatformTuple::current();
    let placeholder = compute_install_hash_v8(
        pkg_content,
        &lock_content,
        file_link_bytes.as_ref(),
        lpm_linker::LinkerMode::Isolated,
        ObjectIntegrityPolicy::Source,
        &platform,
    );
    InstallState {
        up_to_date: false,
        hash: Some(placeholder),
    }
}

fn invalid_integrity_state(
    project_dir: &Path,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
) -> InstallState {
    let lock_content =
        crate::commands::install::workspace_lockfile::active_lockfile_content(project_dir);
    let file_link_bytes = collect_file_link_manifest_bytes_shared(project_dir, pkg_content);
    let platform = PlatformTuple::current();
    let placeholder = compute_install_hash_v8(
        pkg_content,
        &lock_content,
        file_link_bytes.as_ref(),
        linker_mode,
        ObjectIntegrityPolicy::Source,
        &platform,
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
    check_install_state_with_linker_and_integrity(
        project_dir,
        pkg_content,
        linker_mode,
        ObjectIntegrityPolicy::Source,
    )
}

/// Same as [`check_install_state_with_linker`] but also accepts the
/// resolved v2 object integrity policy. Used by the install pipeline,
/// which already resolved both config dimensions and needs the
/// freshness check to invalidate when either one changes.
pub fn check_install_state_with_linker_and_integrity(
    project_dir: &Path,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
) -> InstallState {
    check_install_state_with_linker_integrity_and_dependency_engine(
        project_dir,
        pkg_content,
        linker_mode,
        object_integrity_policy,
        "none",
        lpm_store::StoreVersion::from_env(),
    )
}

pub(crate) fn check_install_state_with_linker_integrity_and_dependency_engine(
    project_dir: &Path,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    dependency_engine_key: &str,
    store_version: lpm_store::StoreVersion,
) -> InstallState {
    check_install_state_with_linker_integrity_dependency_engine_and_security_analysis(
        project_dir,
        pkg_content,
        linker_mode,
        object_integrity_policy,
        dependency_engine_key,
        store_version,
        crate::source_analysis_config::DEFAULT_SECURITY_ANALYSIS_POLICY,
    )
}

pub(crate) fn check_install_state_with_linker_integrity_dependency_engine_and_security_analysis(
    project_dir: &Path,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    dependency_engine_key: &str,
    store_version: lpm_store::StoreVersion,
    security_analysis_policy: SecurityAnalysisPolicy,
) -> InstallState {
    check_install_state_with_paths(
        FreshnessPaths {
            project_dir,
            lockfile: None,
        },
        pkg_content,
        linker_mode,
        object_integrity_policy,
        store_version,
        InstallHashContext {
            dependency_engine_key,
            security_analysis_policy,
        },
        true,
    )
}

pub(crate) fn check_install_state_with_lockfile(
    project_dir: &Path,
    pkg_content: &str,
    lockfile: &lpm_lockfile::ProjectLockfile,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    store_version: lpm_store::StoreVersion,
    hash_context: InstallHashContext<'_>,
) -> InstallState {
    check_install_state_with_paths(
        FreshnessPaths {
            project_dir,
            lockfile: Some(lockfile),
        },
        pkg_content,
        linker_mode,
        object_integrity_policy,
        store_version,
        hash_context,
        false,
    )
}

fn check_install_state_with_paths(
    paths: FreshnessPaths<'_>,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    store_version: lpm_store::StoreVersion,
    hash_context: InstallHashContext<'_>,
    allow_mtime_fast_path: bool,
) -> InstallState {
    let project_dir = paths.project_dir;
    let platform = PlatformTuple::current();
    if allow_mtime_fast_path
        && let Some(state) = try_mtime_fast_path(
            paths,
            pkg_content,
            linker_mode,
            object_integrity_policy,
            &platform,
            store_version,
            hash_context,
        )
    {
        return state;
    }

    let lock_path = paths.lockfile_path();
    let hash_file = project_dir.join(".lpm").join("install-hash");
    let nm = project_dir.join("node_modules");

    // Read lockfile — empty string if missing (hash will mismatch → needs install)
    let lock_content = paths.lockfile.map_or_else(
        || crate::commands::install::workspace_lockfile::active_lockfile_content(project_dir),
        |project| std::sync::Arc::from(project.lockfile.to_toml().unwrap_or_default()),
    );
    // Local directory source manifests participate in freshness. Empty
    // bytes for projects without local-source deps preserve the common
    // no-local-source path.
    let file_link_bytes = collect_file_link_manifest_bytes_shared(project_dir, pkg_content);
    let current_hash = compute_install_hash_v10(
        pkg_content,
        &lock_content,
        file_link_bytes.as_ref(),
        linker_mode,
        object_integrity_policy,
        &platform,
        hash_context,
    );

    // Validate that package.json parses into the typed PackageJson struct —
    // the same deserialization the full install path uses via read_package_json().
    // A generic serde_json::Value check is NOT sufficient: it accepts invalid
    // LPM config values that the typed parse must still reject.
    //
    // The hash is still returned as Some so callers like dev.rs::needs_install()
    // know the file exists and can trigger a full install which surfaces the error.
    if serde_json::from_str::<lpm_workspace::PackageJson>(lpm_common::strip_utf8_bom_str(
        pkg_content,
    ))
    .is_err()
    {
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

    // v1 → virtual-store layout migration gate. After the default flip, an
    // upgrade-in-place user (still with
    // v1's `<project>/.lpm/wrappers/` or `<project>/.lpm/hoisted/`
    // populated) needs the install pipeline to run the v1→virtual-store wipe-
    // and-rebuild sequence. Without this gate the sync fast lane in
    // `main.rs` short-circuits with "up to date" and the user's
    // project stays on the legacy layout indefinitely. The dual-gate
    // shape mirrors D8c: legacy state populated + new
    // store version active = freshness reset.
    //
    // Detection mirrors the install-pipeline's
    // [`commands::install::needs_virtual_store_migration`] but is duplicated
    // here intentionally: importing the install module from
    // install_state would create a cyclic-ish coupling for one
    // two-line predicate, and the predicate is small enough that
    // drift won't realistically diverge.
    if store_version.uses_virtual_store() {
        let legacy_isolated = project_dir.join(".lpm").join("wrappers");
        let legacy_hoisted = project_dir.join(".lpm").join("hoisted");
        if legacy_isolated.exists() || legacy_hoisted.exists() {
            return InstallState {
                up_to_date: false,
                hash: Some(current_hash),
            };
        }
    }
    if project_uses_other_virtual_store(project_dir, store_version) {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // Hash comparison — read only the first line of the file so v1 (bare
    // hash) and v2 (hash + mtime line) formats both parse identically.
    let Ok(cached_hash_file) =
        lpm_common::read_text_file_capped(&hash_file, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    };
    let cached_hash = cached_hash_file.lines().next().unwrap_or("").trim();
    if cached_hash != current_hash
        || !bin_shims_current(&cached_hash_file)
        || !store_keys_current(&cached_hash_file)
        || !install_script_rules_current(&cached_hash_file)
    {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    if obsolete_binary_lockfile_remains(&lock_path) {
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

/// Whether the install recorded in `install_hash` wrote command shims the
/// way this release does. On Windows a project linked before `.cmd` shims
/// named their targets from `%dp0%` has shims that break for a non-ASCII
/// user folder, or none at all under a path with `'` or `&`, so it is linked
/// again once; elsewhere shims haven't changed.
fn bin_shims_current(install_hash: &str) -> bool {
    !cfg!(windows)
        || install_hash
            .lines()
            .any(|line| line.strip_prefix("s:") == Some(lpm_linker::BIN_SHIM_FORMAT))
}

/// Whether the install recorded in `install_hash` linked the project to
/// store entries under the key schema this release derives. Entries under
/// an earlier schema are not found again, and one written before a key
/// covered its package's bytes may hold what another project installed, so
/// the project is linked again once.
fn store_keys_current(install_hash: &str) -> bool {
    install_hash
        .lines()
        .any(|line| line.strip_prefix("k:") == Some(lpm_store::v2::GraphKey::SCHEMA_VERSION))
}

/// Whether the install recorded in `install_hash` read its packages'
/// install-time scripts under the rules this release reads them by (see
/// [`lpm_security::INSTALL_SCRIPT_RULES`]).
fn install_script_rules_current(install_hash: &str) -> bool {
    install_hash
        .lines()
        .any(|line| line.strip_prefix("r:") == Some(lpm_security::INSTALL_SCRIPT_RULES))
}

fn project_uses_other_virtual_store(project_dir: &Path, selected: lpm_store::StoreVersion) -> bool {
    let Ok(lpm_root) = lpm_common::LpmRoot::from_env() else {
        return false;
    };
    let other_links = match selected {
        lpm_store::StoreVersion::V1 => return false,
        lpm_store::StoreVersion::V2 => {
            lpm_store::v2::StoreV2Paths::from_lpm_root_v3(&lpm_root).links_root()
        }
        lpm_store::StoreVersion::V3 => {
            lpm_store::v2::StoreV2Paths::from_lpm_root(&lpm_root).links_root()
        }
    };
    lpm_linker::LayoutPaths::for_project(project_dir).is_v2_install(&other_links)
}

#[derive(Clone, Copy)]
struct FreshnessPaths<'a> {
    project_dir: &'a Path,
    lockfile: Option<&'a lpm_lockfile::ProjectLockfile>,
}

impl<'a> FreshnessPaths<'a> {
    fn lockfile_path(self) -> std::borrow::Cow<'a, Path> {
        self.lockfile.map_or_else(
            || {
                std::borrow::Cow::Owned(
                    crate::commands::install::workspace_lockfile::active_lockfile_path(
                        self.project_dir,
                    ),
                )
            },
            |project| std::borrow::Cow::Borrowed(project.path.as_path()),
        )
    }
}

const SYNC_NOOP_PROOF_VERSION_V2: &str = "v2";
const SYNC_NOOP_PROOF_VERSION: &str = "v3";
const SYNC_NOOP_FLAG_ELIGIBLE: u8 = 1 << 0;
const SYNC_NOOP_FLAG_HAS_NODE_ENGINES: u8 = 1 << 1;
const SYNC_NOOP_FLAG_AUTO_INSTALL_PEERS: u8 = 1 << 2;
const SYNC_NOOP_FLAG_FROZEN_OK: u8 = 1 << 3;
const SYNC_NOOP_FLAGS_MASK: u8 = SYNC_NOOP_FLAG_ELIGIBLE
    | SYNC_NOOP_FLAG_HAS_NODE_ENGINES
    | SYNC_NOOP_FLAG_AUTO_INSTALL_PEERS
    | SYNC_NOOP_FLAG_FROZEN_OK;

/// Regular-file identity stamp captured without following symlinks so
/// unchanged standalone manifests/lockfiles can skip re-reading and hashing
/// `lpm.lock` when their stamps match and are strictly older than
/// `.lpm/install-hash`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SyncNoopFileStamp {
    pub(crate) len: u64,
    pub(crate) mtime_ns: u64,
    pub(crate) ctime_ns: u64,
    pub(crate) dev: u64,
    pub(crate) ino: u128,
}

impl SyncNoopFileStamp {
    pub(crate) fn from_path(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        {
            let meta = std::fs::symlink_metadata(path).ok()?;
            Self::from_symlink_metadata(&meta)
        }
        #[cfg(windows)]
        {
            let stamp = lpm_common::windows_regular_file_stamp_from_path(path)?;
            Some(Self::from_windows_stamp(stamp))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            None
        }
    }

    #[cfg(windows)]
    fn from_windows_stamp(stamp: lpm_common::WindowsFileStamp) -> Self {
        Self {
            len: stamp.len,
            mtime_ns: stamp.mtime_ns,
            ctime_ns: stamp.ctime_ns,
            dev: stamp.identity.volume,
            ino: stamp.identity.file_id,
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn from_symlink_metadata(meta: &std::fs::Metadata) -> Option<Self> {
        if meta.file_type().is_symlink() {
            return None;
        }
        Self::from_regular_metadata(meta)
    }

    #[cfg(not(windows))]
    fn from_regular_metadata(meta: &std::fs::Metadata) -> Option<Self> {
        #[cfg(not(unix))]
        {
            let _ = meta;
            None
        }
        #[cfg(unix)]
        {
            if !meta.is_file() {
                return None;
            }
            let modified = meta.modified().ok()?;
            let mtime_ns = modified.duration_since(UNIX_EPOCH).ok()?.as_nanos() as u64;
            use std::os::unix::fs::MetadataExt as _;
            let sec = u64::try_from(meta.ctime()).ok()?;
            let nsec = u64::try_from(meta.ctime_nsec()).ok()?;
            Some(Self {
                len: meta.len(),
                mtime_ns,
                ctime_ns: sec.saturating_mul(1_000_000_000).saturating_add(nsec),
                dev: meta.dev(),
                ino: u128::from(meta.ino()),
            })
        }
    }

    /// True when this file was last modified/changed strictly before the
    /// `.lpm/install-hash` stamp (guarding against same-quantum racily-clean edits).
    pub(crate) fn is_strictly_older_than(self, hash_stamp: Self) -> bool {
        self.mtime_ns < hash_stamp.mtime_ns && self.ctime_ns < hash_stamp.ctime_ns
    }

    /// True when both file timestamps are strictly in the past relative to
    /// `now_ns`, ensuring a rewrite of `.lpm/install-hash` can move past them
    /// instead of looping on future-dated timestamps.
    pub(crate) fn is_strictly_older_than_wall_clock(self, now_ns: u64) -> bool {
        self.mtime_ns < now_ns && self.ctime_ns < now_ns
    }

    fn format_compact(self) -> String {
        format!(
            "{},{},{},{},{}",
            self.len, self.mtime_ns, self.ctime_ns, self.dev, self.ino
        )
    }

    fn parse_compact(raw: &str) -> Option<Self> {
        let mut parts = raw.split(',');
        let len = parts.next()?.parse::<u64>().ok()?;
        let mtime_ns = parts.next()?.parse::<u64>().ok()?;
        let ctime_ns = parts.next()?.parse::<u64>().ok()?;
        let dev = parts.next()?.parse::<u64>().ok()?;
        let ino = parts.next()?.parse::<u128>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            len,
            mtime_ns,
            ctime_ns,
            dev,
            ino,
        })
    }
}

#[cfg(any(unix, windows, test))]
fn verified_descriptor_stamp(
    pre_fd: Option<SyncNoopFileStamp>,
    post_fd: Option<SyncNoopFileStamp>,
    post_path: Option<SyncNoopFileStamp>,
    byte_len: u64,
) -> Option<SyncNoopFileStamp> {
    let stamp = pre_fd?;
    (post_fd == Some(stamp) && post_path == Some(stamp) && stamp.len == byte_len).then_some(stamp)
}

pub(crate) fn read_regular_file_capped_with_stamp(
    path: &Path,
    cap: u64,
) -> Result<(Vec<u8>, Option<SyncNoopFileStamp>), lpm_common::BoundedReadError> {
    #[cfg(unix)]
    {
        let mut file = match lpm_common::open_nofollow(path) {
            Ok(file) => file,
            Err(source)
                if matches!(
                    source.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::EMLINK)
                ) =>
            {
                // Symlinked manifests remain readable without blocking on special files,
                // and never receive a regular-file stamp.
                let (bytes, _) = lpm_common::read_regular_file_capped_with_metadata(path, cap)?;
                return Ok((bytes, None));
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(lpm_common::BoundedReadError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(lpm_common::BoundedReadError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let pre_meta = file
            .metadata()
            .map_err(|source| lpm_common::BoundedReadError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if !pre_meta.is_file() {
            return Err(lpm_common::BoundedReadError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"),
            });
        }
        if pre_meta.len() > cap {
            return Err(lpm_common::BoundedReadError::TooLarge {
                path: path.to_path_buf(),
                limit: cap,
            });
        }
        let pre_fd = SyncNoopFileStamp::from_regular_metadata(&pre_meta);
        let bytes = lpm_common::read_opened_file_capped(&mut file, path, cap, pre_meta.len())?;
        let post_fd = file
            .metadata()
            .ok()
            .and_then(|meta| SyncNoopFileStamp::from_regular_metadata(&meta));
        let post_path = SyncNoopFileStamp::from_path(path);
        let stamp = verified_descriptor_stamp(pre_fd, post_fd, post_path, bytes.len() as u64);
        Ok((bytes, stamp))
    }
    #[cfg(windows)]
    {
        let mut file = match lpm_common::open_nofollow(path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(lpm_common::BoundedReadError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(_) => {
                let bytes = lpm_common::read_file_capped(path, cap)?;
                return Ok((bytes, None));
            }
        };
        let pre_meta = file
            .metadata()
            .map_err(|source| lpm_common::BoundedReadError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if lpm_common::is_symlink_or_junction(&pre_meta) {
            drop(file);
            let bytes = lpm_common::read_file_capped(path, cap)?;
            return Ok((bytes, None));
        }
        if !pre_meta.is_file() {
            return Err(lpm_common::BoundedReadError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"),
            });
        }
        if pre_meta.len() > cap {
            return Err(lpm_common::BoundedReadError::TooLarge {
                path: path.to_path_buf(),
                limit: cap,
            });
        }
        let pre_fd = lpm_common::windows_regular_file_stamp_from_open_file(&file)
            .map(SyncNoopFileStamp::from_windows_stamp);
        let bytes = lpm_common::read_opened_file_capped(&mut file, path, cap, pre_meta.len())?;
        let post_fd = lpm_common::windows_regular_file_stamp_from_open_file(&file)
            .map(SyncNoopFileStamp::from_windows_stamp);
        let post_path = SyncNoopFileStamp::from_path(path);
        let stamp = verified_descriptor_stamp(pre_fd, post_fd, post_path, bytes.len() as u64);
        Ok((bytes, stamp))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let bytes = lpm_common::read_file_capped(path, cap)?;
        Ok((bytes, None))
    }
}

pub(crate) fn read_text_regular_file_capped_with_stamp(
    path: &Path,
    cap: u64,
) -> Result<(String, Option<SyncNoopFileStamp>), lpm_common::BoundedReadError> {
    let (bytes, stamp) = read_regular_file_capped_with_stamp(path, cap)?;
    let text =
        String::from_utf8(bytes).map_err(|source| lpm_common::BoundedReadError::InvalidUtf8 {
            path: path.to_path_buf(),
            source: source.utf8_error(),
        })?;
    Ok((text, stamp))
}

/// Checks that `content` is a valid JSON object without a top-level
/// `"workspaces"` property, using a zero-allocation key visitor (no `String`
/// allocations for unescaped keys, while still decoding JSON escapes such as
/// `"\u0077orkspaces"` and rejecting malformed JSON).
pub(crate) fn is_non_workspace_package_json_object(content: &str) -> bool {
    struct KeyIsWorkspaces(bool);

    impl<'de> serde::Deserialize<'de> for KeyIsWorkspaces {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct KeyVisitor;
            impl serde::de::Visitor<'_> for KeyVisitor {
                type Value = KeyIsWorkspaces;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a JSON object key")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(KeyIsWorkspaces(value == "workspaces"))
                }

                fn visit_borrowed_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(KeyIsWorkspaces(value == "workspaces"))
                }
            }
            deserializer.deserialize_str(KeyVisitor)
        }
    }

    struct NonWorkspaceObjectVisitor;

    impl<'de> serde::de::Visitor<'de> for NonWorkspaceObjectVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a package.json object")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut has_workspaces = false;
            while let Some(KeyIsWorkspaces(is_ws)) = map.next_key::<KeyIsWorkspaces>()? {
                if is_ws {
                    has_workspaces = true;
                }
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
            Ok(!has_workspaces)
        }
    }

    struct NonWorkspaceObject(bool);

    impl<'de> serde::Deserialize<'de> for NonWorkspaceObject {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer
                .deserialize_map(NonWorkspaceObjectVisitor)
                .map(Self)
        }
    }

    serde_json::from_str::<NonWorkspaceObject>(lpm_common::strip_utf8_bom_str(content))
        .is_ok_and(|parsed| parsed.0)
}

pub(crate) fn sync_noop_content_digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..16])
}

fn is_lower_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Content-bound lockfile-summary proof stored on the optional `f:` line of
/// `.lpm/install-hash` so the synchronous up-to-date fast lane can verify
/// unchanged standalone installs without parsing `lpm.lock` TOML.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SyncNoopLockfileProof {
    pub(crate) lockfile_version: u32,
    pub(crate) pkg_digest: String,
    pub(crate) lock_digest: String,
    pub(crate) lockfile_eligible: bool,
    pub(crate) has_node_engines: bool,
    pub(crate) auto_install_peers: bool,
    pub(crate) frozen_ok: bool,
    pub(crate) routes_fingerprint: String,
    pub(crate) pkg_stamp: Option<SyncNoopFileStamp>,
    pub(crate) lock_stamp: Option<SyncNoopFileStamp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SyncNoopLockfileProofInput {
    pub(crate) pkg_digest: String,
    pub(crate) lock_digest: String,
    pub(crate) lockfile_eligible: bool,
    pub(crate) has_node_engines: bool,
    pub(crate) auto_install_peers: bool,
    pub(crate) frozen_ok: bool,
    pub(crate) routes_fingerprint: String,
    pub(crate) pkg_stamp: Option<SyncNoopFileStamp>,
    pub(crate) lock_stamp: Option<SyncNoopFileStamp>,
}

impl SyncNoopLockfileProof {
    fn from_input(input: &SyncNoopLockfileProofInput) -> Self {
        Self {
            lockfile_version: lpm_lockfile::LOCKFILE_VERSION,
            pkg_digest: input.pkg_digest.clone(),
            lock_digest: input.lock_digest.clone(),
            lockfile_eligible: input.lockfile_eligible,
            has_node_engines: input.has_node_engines,
            auto_install_peers: input.auto_install_peers,
            frozen_ok: input.frozen_ok,
            routes_fingerprint: input.routes_fingerprint.clone(),
            pkg_stamp: input.pkg_stamp,
            lock_stamp: input.lock_stamp,
        }
    }

    fn format_line_value(&self) -> String {
        let mut flags = 0u8;
        if self.lockfile_eligible {
            flags |= SYNC_NOOP_FLAG_ELIGIBLE;
        }
        if self.has_node_engines {
            flags |= SYNC_NOOP_FLAG_HAS_NODE_ENGINES;
        }
        if self.auto_install_peers {
            flags |= SYNC_NOOP_FLAG_AUTO_INSTALL_PEERS;
        }
        if self.frozen_ok {
            flags |= SYNC_NOOP_FLAG_FROZEN_OK;
        }
        if let (Some(pkg_stamp), Some(lock_stamp)) = (self.pkg_stamp, self.lock_stamp) {
            format!(
                "{SYNC_NOOP_PROOF_VERSION}:{}:{}:{}:{flags:02x}:{}:{}:{}",
                self.lockfile_version,
                self.pkg_digest,
                self.lock_digest,
                self.routes_fingerprint,
                pkg_stamp.format_compact(),
                lock_stamp.format_compact(),
            )
        } else {
            format!(
                "{SYNC_NOOP_PROOF_VERSION_V2}:{}:{}:{}:{flags:02x}:{}",
                self.lockfile_version, self.pkg_digest, self.lock_digest, self.routes_fingerprint
            )
        }
    }

    pub(crate) fn parse_from_state(content: &str) -> Option<Self> {
        let mut parsed = None;
        for line in content.lines() {
            let Some(rest) = line.strip_prefix("f:") else {
                continue;
            };
            if parsed.is_some() {
                return None;
            }
            let mut parts = rest.split(':');
            let version_tag = parts.next()?;
            let is_v3 = match version_tag {
                SYNC_NOOP_PROOF_VERSION => true,
                SYNC_NOOP_PROOF_VERSION_V2 => false,
                _ => return None,
            };
            let lockfile_version = parts.next()?.parse::<u32>().ok()?;
            if lockfile_version != lpm_lockfile::LOCKFILE_VERSION {
                return None;
            }
            let pkg_digest = parts.next()?;
            let lock_digest = parts.next()?;
            let flags = u8::from_str_radix(parts.next()?, 16).ok()?;
            let routes_fingerprint = parts.next()?;
            let (pkg_stamp, lock_stamp) = if is_v3 {
                let pkg = SyncNoopFileStamp::parse_compact(parts.next()?)?;
                let lock = SyncNoopFileStamp::parse_compact(parts.next()?)?;
                (Some(pkg), Some(lock))
            } else {
                (None, None)
            };
            if parts.next().is_some()
                || flags & !SYNC_NOOP_FLAGS_MASK != 0
                || !is_lower_hex(pkg_digest, 32)
                || !is_lower_hex(lock_digest, 32)
                || !is_lower_hex(routes_fingerprint, 16)
            {
                return None;
            }
            parsed = Some(Self {
                lockfile_version,
                pkg_digest: pkg_digest.to_string(),
                lock_digest: lock_digest.to_string(),
                lockfile_eligible: flags & SYNC_NOOP_FLAG_ELIGIBLE != 0,
                has_node_engines: flags & SYNC_NOOP_FLAG_HAS_NODE_ENGINES != 0,
                auto_install_peers: flags & SYNC_NOOP_FLAG_AUTO_INSTALL_PEERS != 0,
                frozen_ok: flags & SYNC_NOOP_FLAG_FROZEN_OK != 0,
                routes_fingerprint: routes_fingerprint.to_string(),
                pkg_stamp,
                lock_stamp,
            });
        }
        parsed
    }
}

/// Record or update the `f:` proof line in an existing `.lpm/install-hash`
/// file without changing any other metadata line. When `force_refresh` is true,
/// rewrites `.lpm/install-hash` even when the formatted proof text already
/// matches so a same-tick timestamp collision can self-heal onto the stamp path.
/// When `expected_header` is supplied, aborts cleanly if `.lpm/install-hash`
/// was concurrently modified by another install.
pub(crate) fn backfill_install_hash_sync_noop_proof_with_refresh(
    project_dir: &Path,
    proof_input: &SyncNoopLockfileProofInput,
    force_refresh: bool,
    expected_header: Option<(&str, &str, Option<SyncNoopFileStamp>)>,
) -> std::io::Result<bool> {
    let lock_path = lpm_common::project_install_lock(project_dir);
    let Ok(Some(_install_lock)) = lpm_common::try_acquire_exclusive_lock(lock_path) else {
        return Ok(false);
    };
    let hash_path = project_dir.join(".lpm").join("install-hash");
    let (content, current_stamp) = match read_text_regular_file_capped_with_stamp(
        &hash_path,
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(read) => read,
        Err(_) => return Ok(false),
    };
    if let Some((expected_hash, expected_mtime, expected_stamp)) = expected_header {
        let mut lines = content.lines();
        if lines.next() != Some(expected_hash) || lines.next() != Some(expected_mtime) {
            return Ok(false);
        }
        if expected_stamp.is_some() && current_stamp != expected_stamp {
            return Ok(false);
        }
    }
    let proof = SyncNoopLockfileProof::from_input(proof_input);
    let new_line = format!("f:{}", proof.format_line_value());
    let mut updated = String::with_capacity(content.len() + new_line.len() + 1);
    let mut replaced = false;
    for line in content.lines() {
        if line.starts_with("f:") {
            if !replaced {
                updated.push_str(&new_line);
                updated.push('\n');
                replaced = true;
            }
            continue;
        }
        updated.push_str(line);
        updated.push('\n');
    }
    if !replaced {
        updated.push_str(&new_line);
        updated.push('\n');
    }
    if updated == content && !force_refresh {
        return Ok(false);
    }
    write_state_file_owner_only(&hash_path, updated.as_bytes())?;
    Ok(true)
}

pub(crate) struct CachedMtimeMatch {
    pub(crate) lock_size: u64,
    pub(crate) pkg_stamp: Option<SyncNoopFileStamp>,
    pub(crate) lock_stamp: Option<SyncNoopFileStamp>,
    pub(crate) hash_stamp: Option<SyncNoopFileStamp>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn check_cached_state_mtime_match(
    project_dir: &Path,
    lock_path: &Path,
    pkg_content: &str,
    cached_state: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    store_version: lpm_store::StoreVersion,
    context: InstallHashContext<'_>,
) -> Option<CachedMtimeMatch> {
    let platform = PlatformTuple::current();
    try_mtime_fast_path_with_cached_content(
        project_dir,
        lock_path,
        pkg_content,
        Some(cached_state),
        linker_mode,
        object_integrity_policy,
        &platform,
        store_version,
        context,
    )
    .map(|(_, sizes)| sizes)
}

fn try_mtime_fast_path(
    paths: FreshnessPaths<'_>,
    pkg_content: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    store_version: lpm_store::StoreVersion,
    context: InstallHashContext<'_>,
) -> Option<InstallState> {
    let lock_path = paths.lockfile_path();
    try_mtime_fast_path_with_cached_content(
        paths.project_dir,
        &lock_path,
        pkg_content,
        None,
        linker_mode,
        object_integrity_policy,
        platform,
        store_version,
        context,
    )
    .map(|(state, _)| state)
}

#[allow(clippy::too_many_arguments)]
fn try_mtime_fast_path_with_cached_content(
    project_dir: &Path,
    lock_path: &Path,
    pkg_content: &str,
    cached_state: Option<&str>,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    store_version: lpm_store::StoreVersion,
    context: InstallHashContext<'_>,
) -> Option<(InstallState, CachedMtimeMatch)> {
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

    // v1 → virtual-store migration gate. Must mirror
    // the slow-path guard in `check_install_state_with_content`
    // because the mtime fast lane skips that function entirely on
    // mtime hits. Without this, an upgrade-in-place user whose
    // package.json + lpm.lock mtimes haven't changed would
    // permanently short-circuit at "up to date" and never run the
    // v1 → virtual-store wipe-and-rebuild sequence.
    if store_version.uses_virtual_store() {
        let legacy_isolated = project_dir.join(".lpm").join("wrappers");
        let legacy_hoisted = project_dir.join(".lpm").join("hoisted");
        if legacy_isolated.exists() || legacy_hoisted.exists() {
            return None;
        }
    }
    if project_uses_other_virtual_store(project_dir, store_version) {
        return None;
    }

    let hash_file = project_dir.join(".lpm").join("install-hash");
    let owned_content;
    let content = match cached_state {
        Some(content) => content,
        None => {
            owned_content = lpm_common::read_text_file_capped(
                &hash_file,
                lpm_common::STATE_FILE_SIZE_CAP_BYTES,
            )
            .ok()?;
            &owned_content
        }
    };
    if !bin_shims_current(content)
        || !store_keys_current(content)
        || !install_script_rules_current(content)
    {
        return None;
    }

    let mut lines = content.lines();
    let stored_hash = lines.next()?.trim();
    // v1 files have no second line → no mtime fast path available.
    let mtime_line = lines.next()?;
    let rest = mtime_line.strip_prefix("m:")?;
    let (pkg_ns_str, lock_ns_str) = rest.split_once(':')?;
    let stored_pkg_ns: u64 = pkg_ns_str.parse().ok()?;
    let stored_lock_ns: u64 = lock_ns_str.parse().ok()?;

    // v8: the install-hash carries `l:<linker_mode>`,
    // `i:<source|tree>`, and `p:<os>/<cpu>/<libc>` lines so the mtime
    // fast path can detect config or host-platform flips without
    // recomputing the full SHA-256.
    // Missing metadata means a legacy file; bail to the slow path where
    // the schema tag mismatch forces re-install.
    let linker_line = lines.next()?;
    let stored_linker = linker_line.strip_prefix("l:")?;
    if stored_linker != linker_mode.as_str() {
        return None;
    }

    let integrity_line = lines.next()?;
    let stored_integrity_policy = integrity_line.strip_prefix("i:")?;
    if stored_integrity_policy != object_integrity_policy.as_str() {
        return None;
    }

    let platform_line = lines.next()?;
    let stored_platform = platform_line.strip_prefix("p:")?;
    if stored_platform != platform_tuple_key(platform) {
        return None;
    }

    let source_analysis_line = lines.next()?;
    if source_analysis_line.strip_prefix("a:")? != context.security_analysis_policy.as_str() {
        return None;
    }

    match lines.next() {
        Some(engine_line) => {
            if engine_line.strip_prefix("e:")? != context.dependency_engine_key {
                return None;
            }
        }
        None if context.dependency_engine_key == "none" => {}
        None => return None,
    }

    let pkg_path = project_dir.join("package.json");
    let pkg_lmeta = std::fs::symlink_metadata(&pkg_path).ok()?;
    let (pkg_ns, pkg_is_regular) = if lpm_common::is_symlink_or_junction(&pkg_lmeta) {
        (mtime_ns_and_len(&pkg_path)?.0, false)
    } else if pkg_lmeta.is_file() {
        (mtime_ns_from_metadata(&pkg_lmeta)?, true)
    } else {
        return None;
    };
    // lpm.lock may be absent on a never-installed fast-lane entry; 0
    // sentinel lines up with the writer's convention.
    let (lock_ns, lock_size, lock_regular_meta) = match std::fs::symlink_metadata(lock_path) {
        Ok(meta) if lpm_common::is_symlink_or_junction(&meta) => {
            let (ns, len) = mtime_ns_and_len(lock_path).unwrap_or((0, 0));
            (ns, len, None)
        }
        Ok(meta) if meta.is_file() => {
            let ns = mtime_ns_from_metadata(&meta).unwrap_or(0);
            let len = meta.len();
            (ns, len, Some(meta))
        }
        _ => (0, 0, None),
    };

    if pkg_ns != stored_pkg_ns || lock_ns != stored_lock_ns {
        return None;
    }

    let pkg_stamp = if pkg_is_regular {
        #[cfg(windows)]
        {
            SyncNoopFileStamp::from_path(&pkg_path)
        }
        #[cfg(not(windows))]
        {
            SyncNoopFileStamp::from_symlink_metadata(&pkg_lmeta)
        }
    } else {
        None
    };
    let lock_stamp = match lock_regular_meta {
        Some(meta) => {
            #[cfg(windows)]
            {
                let _ = meta;
                SyncNoopFileStamp::from_path(lock_path)
            }
            #[cfg(not(windows))]
            {
                SyncNoopFileStamp::from_symlink_metadata(&meta)
            }
        }
        None => None,
    };

    match parse_verified_file_stamps(content) {
        VerifiedFileStampsParse::Valid(expected_pkg_stamp, expected_lock_stamp) => {
            if pkg_stamp != Some(expected_pkg_stamp) || lock_stamp != expected_lock_stamp {
                return None;
            }
            if expected_lock_stamp.is_none() && lock_ns != 0 {
                return None;
            }
        }
        VerifiedFileStampsParse::Malformed => return None,
        VerifiedFileStampsParse::Absent => {}
    }

    if obsolete_binary_lockfile_remains(lock_path) {
        return None;
    }

    // External-modification check: if anything under node_modules was
    // touched more recently than the hash file, the recorded state
    // cannot be trusted even with matching manifest mtimes.
    let nm_ns = mtime_ns(&nm)?;
    let hash_lmeta = std::fs::symlink_metadata(&hash_file).ok()?;
    let (hash_ns, hash_is_regular) = if lpm_common::is_symlink_or_junction(&hash_lmeta) {
        (mtime_ns(&hash_file)?, false)
    } else if hash_lmeta.is_file() {
        (mtime_ns_from_metadata(&hash_lmeta)?, true)
    } else {
        return None;
    };
    if nm_ns > hash_ns {
        return None;
    }
    let hash_stamp = if hash_is_regular {
        #[cfg(windows)]
        {
            SyncNoopFileStamp::from_path(&hash_file)
        }
        #[cfg(not(windows))]
        {
            SyncNoopFileStamp::from_symlink_metadata(&hash_lmeta)
        }
    } else {
        None
    };

    Some((
        InstallState {
            up_to_date: true,
            hash: Some(stored_hash.to_string()),
        },
        CachedMtimeMatch {
            lock_size,
            pkg_stamp,
            lock_stamp,
            hash_stamp,
        },
    ))
}

pub(crate) fn package_json_needs_slow_freshness(pkg_content: &str) -> bool {
    pkg_content.contains("\"file:")
        || pkg_content.contains("\"link:")
        || pkg_content.contains("\"workspaces\"")
}

fn mtime_ns_from_metadata(metadata: &std::fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    // `as_nanos` returns u128; narrow to u64 — safe until year 2554.
    Some(dur.as_nanos() as u64)
}

/// Return the modified-time (nanoseconds since Unix epoch) and byte length of
/// `path` from a single `stat` syscall.
fn mtime_ns_and_len(path: &Path) -> Option<(u64, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((mtime_ns_from_metadata(&metadata)?, metadata.len()))
}

/// Return the modified-time of `path` as nanoseconds since the Unix
/// epoch. Returns `None` if the file is missing or the filesystem does
/// not expose mtime (neither of which should happen for the files the
/// install-state machinery cares about).
fn mtime_ns(path: &Path) -> Option<u64> {
    mtime_ns_and_len(path).map(|(ns, _)| ns)
}

/// An install has to run while an `lpm.lockb` from an earlier LPM CLI sits
/// beside the lockfile, because the install is what removes it.
fn obsolete_binary_lockfile_remains(lockfile_path: &Path) -> bool {
    if !lockfile_path.exists() {
        return false;
    }
    let binary_path = lockfile_path.with_file_name(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME);
    match std::fs::symlink_metadata(&binary_path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Write `.lpm/install-hash` using the default source-integrity policy.
/// Production install code should use [`write_install_hash_with_integrity`]
/// after resolving the effective config chain.
pub fn write_install_hash(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
) -> std::io::Result<()> {
    write_install_hash_with_integrity(
        project_dir,
        hash,
        linker_mode,
        ObjectIntegrityPolicy::Source,
    )
}

/// Write `.lpm/install-hash` with the freshness hash plus mtime, linker,
/// integrity-policy, platform, and dependency-engine metadata.
/// Callers provide the pre-computed hash, the linker mode, and the v2 object
/// integrity policy that were effective for the install. The metadata lets the
/// mtime fast path detect config, host-platform, and dependency-engine context
/// changes without recomputing the full SHA-256 or parsing the lockfile.
///
/// On any failure reading an mtime (typically missing lpm.lock on a
/// dependency-less project), falls back to a `0` sentinel. A mismatch
/// between `0`-stored and a later real mtime simply falls through to
/// the full hash path — still correct, just not fast.
///
/// Writes `.lpm/install-hash` atomically via `fs::write`, same as the
/// prior byte-string-only writes — the ManifestTransaction snapshot
/// machinery is unaffected.
pub fn write_install_hash_with_integrity(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
) -> std::io::Result<()> {
    let platform = PlatformTuple::current();
    write_install_hash_with_integrity_and_platform(
        project_dir,
        hash,
        linker_mode,
        object_integrity_policy,
        &platform,
    )
}

pub(crate) fn write_install_hash_with_integrity_and_platform(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
) -> std::io::Result<()> {
    write_install_hash_with_integrity_platform_and_dependency_engine(
        project_dir,
        hash,
        linker_mode,
        object_integrity_policy,
        platform,
        "none",
        None,
    )
}

pub(crate) fn release_age_freshness_key(
    min_age_secs: u64,
    policy: crate::release_age_config::ReleaseAgePolicy,
    excludes: &[String],
    allow_new: bool,
) -> Option<String> {
    if !policy.is_strict() || min_age_secs == 0 || allow_new {
        return None;
    }
    let mut normalized: Vec<&str> = excludes.iter().map(String::as_str).collect();
    normalized.sort_unstable();
    normalized.dedup();
    let mut hasher = Sha256::new();
    for selector in normalized {
        hasher.update(selector.as_bytes());
        hasher.update(b"\x00");
    }
    let digest = hasher.finalize();
    Some(format!(
        "strict:{min_age_secs}:{}",
        hex::encode(&digest[..8])
    ))
}

pub(crate) fn parse_release_age_policy_line(content: &str) -> Option<&str> {
    let mut found = None;
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("g:") else {
            continue;
        };
        if found.is_some() || rest.is_empty() {
            return None;
        }
        found = Some(rest);
    }
    found
}

pub(crate) fn write_install_hash_with_integrity_platform_and_dependency_engine(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    dependency_engine_key: &str,
    node_runtime_fingerprint: Option<&str>,
) -> std::io::Result<()> {
    write_install_hash_with_metadata(
        project_dir,
        hash,
        linker_mode,
        object_integrity_policy,
        platform,
        dependency_engine_key,
        InstallHashWriteMetadata {
            lockfile_path: None,
            node_runtime_fingerprint,
            security_analysis_policy:
                crate::source_analysis_config::DEFAULT_SECURITY_ANALYSIS_POLICY,
            sync_noop_proof: None,
            release_age_policy_key: None,
            mtime_policy: InstallHashMtimePolicy::StatFromDisk,
        },
    )
}

enum VerifiedFileStampsParse {
    Absent,
    Valid(SyncNoopFileStamp, Option<SyncNoopFileStamp>),
    Malformed,
}

fn parse_verified_file_stamps(content: &str) -> VerifiedFileStampsParse {
    let mut found = None;
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("t:") else {
            continue;
        };
        if found.is_some() {
            return VerifiedFileStampsParse::Malformed;
        }
        found = Some(rest);
    }
    let Some(rest) = found else {
        return VerifiedFileStampsParse::Absent;
    };
    let Some((pkg_raw, lock_raw)) = rest.split_once(':') else {
        return VerifiedFileStampsParse::Malformed;
    };
    let Some(pkg_stamp) = SyncNoopFileStamp::parse_compact(pkg_raw) else {
        return VerifiedFileStampsParse::Malformed;
    };
    let lock_stamp = if lock_raw == "none" {
        None
    } else {
        let Some(stamp) = SyncNoopFileStamp::parse_compact(lock_raw) else {
            return VerifiedFileStampsParse::Malformed;
        };
        Some(stamp)
    };
    VerifiedFileStampsParse::Valid(pkg_stamp, lock_stamp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallHashMtimePolicy {
    StatFromDisk,
    Verified {
        pkg_stamp: SyncNoopFileStamp,
        lock_stamp: Option<SyncNoopFileStamp>,
    },
    Disable,
}

pub(crate) struct KnownInstallHashRuntimeState<'a> {
    pub(crate) lockfile_path: &'a Path,
    pub(crate) node_runtime_fingerprint: Option<&'a str>,
    pub(crate) security_analysis_policy: SecurityAnalysisPolicy,
    pub(crate) sync_noop_proof: Option<&'a SyncNoopLockfileProofInput>,
    pub(crate) release_age_policy_key: Option<&'a str>,
}

#[cfg_attr(not(test), expect(dead_code, reason = "used by sync_noop unit tests"))]
pub(crate) fn write_install_hash_with_known_runtime_state(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    dependency_engine_key: &str,
    runtime_state: KnownInstallHashRuntimeState<'_>,
) -> std::io::Result<()> {
    write_install_hash_with_known_runtime_state_and_mtime_policy(
        project_dir,
        hash,
        linker_mode,
        object_integrity_policy,
        platform,
        dependency_engine_key,
        runtime_state,
        InstallHashMtimePolicy::StatFromDisk,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_install_hash_with_known_runtime_state_and_mtime_policy(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    dependency_engine_key: &str,
    runtime_state: KnownInstallHashRuntimeState<'_>,
    mtime_policy: InstallHashMtimePolicy,
) -> std::io::Result<()> {
    write_install_hash_with_metadata(
        project_dir,
        hash,
        linker_mode,
        object_integrity_policy,
        platform,
        dependency_engine_key,
        InstallHashWriteMetadata {
            lockfile_path: Some(runtime_state.lockfile_path),
            node_runtime_fingerprint: runtime_state.node_runtime_fingerprint,
            security_analysis_policy: runtime_state.security_analysis_policy,
            sync_noop_proof: runtime_state.sync_noop_proof,
            release_age_policy_key: runtime_state.release_age_policy_key,
            mtime_policy,
        },
    )
}

struct InstallHashWriteMetadata<'a> {
    lockfile_path: Option<&'a Path>,
    node_runtime_fingerprint: Option<&'a str>,
    security_analysis_policy: SecurityAnalysisPolicy,
    sync_noop_proof: Option<&'a SyncNoopLockfileProofInput>,
    release_age_policy_key: Option<&'a str>,
    mtime_policy: InstallHashMtimePolicy,
}

fn write_install_hash_with_metadata(
    project_dir: &Path,
    hash: &str,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: ObjectIntegrityPolicy,
    platform: &PlatformTuple,
    dependency_engine_key: &str,
    metadata: InstallHashWriteMetadata<'_>,
) -> std::io::Result<()> {
    if metadata
        .node_runtime_fingerprint
        .is_some_and(|value| !is_node_runtime_fingerprint(value))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Node runtime fingerprint",
        ));
    }
    let (mtime_line, verified_stamps_line) = match metadata.mtime_policy {
        InstallHashMtimePolicy::StatFromDisk => {
            let (pkg_ns, _) = mtime_ns_and_len(&project_dir.join("package.json")).unwrap_or((0, 0));
            let lock_path = metadata.lockfile_path.map_or_else(
                || {
                    std::borrow::Cow::Owned(
                        crate::commands::install::workspace_lockfile::active_lockfile_path(
                            project_dir,
                        ),
                    )
                },
                std::borrow::Cow::Borrowed,
            );
            let (lock_ns, _) = mtime_ns_and_len(&lock_path).unwrap_or((0, 0));
            (format!("m:{pkg_ns}:{lock_ns}"), None)
        }
        InstallHashMtimePolicy::Verified {
            pkg_stamp,
            lock_stamp,
        } => {
            let lock_mtime_ns = lock_stamp.map_or(0, |stamp| stamp.mtime_ns);
            let lock_compact =
                lock_stamp.map_or_else(|| "none".to_string(), SyncNoopFileStamp::format_compact);
            (
                format!("m:{}:{lock_mtime_ns}", pkg_stamp.mtime_ns),
                Some(format!("t:{}:{lock_compact}\n", pkg_stamp.format_compact())),
            )
        }
        InstallHashMtimePolicy::Disable => ("m:stale:stale".to_string(), None),
    };

    let hash_dir = lpm_common::ensure_project_state_dir(project_dir)?;
    let linker_str = linker_mode.as_str();
    let integrity_policy_str = object_integrity_policy.as_str();
    let platform_str = platform_tuple_key(platform);
    let security_analysis_str = metadata.security_analysis_policy.as_str();
    let node_runtime_fingerprint = metadata.node_runtime_fingerprint.unwrap_or("none");
    let bin_shim_format = lpm_linker::BIN_SHIM_FORMAT;
    let store_key_schema = lpm_store::v2::GraphKey::SCHEMA_VERSION;
    let install_script_rules = lpm_security::INSTALL_SCRIPT_RULES;
    let mut content = format!(
        "{hash}\n{mtime_line}\nl:{linker_str}\ni:{integrity_policy_str}\np:{platform_str}\na:{security_analysis_str}\ne:{dependency_engine_key}\nn:{node_runtime_fingerprint}\ns:{bin_shim_format}\nk:{store_key_schema}\nr:{install_script_rules}\n"
    );
    if let Some(stamps_line) = verified_stamps_line {
        content.push_str(&stamps_line);
    }
    if let Some(proof_input) = metadata.sync_noop_proof {
        let proof = SyncNoopLockfileProof::from_input(proof_input);
        content.push_str("f:");
        content.push_str(&proof.format_line_value());
        content.push('\n');
    }
    if let Some(release_age_policy_key) = metadata.release_age_policy_key {
        content.push_str("g:");
        content.push_str(release_age_policy_key);
        content.push('\n');
    }
    write_state_file_owner_only(&hash_dir.join("install-hash"), content.as_bytes())?;

    // Manage the "needs-slow-path" sentinel.
    //
    // The mtime fast path checks ONLY root package.json + lpm.lock
    // mtimes — fast and correct for projects whose freshness signal
    // doesn't reach into other manifests. For projects with file: /
    // link: deps OR with workspace members, the install-hash also folds
    // in those manifests' contents, and the mtime fast path can't observe
    // their changes. The sentinel bails the fast path to the slow
    // recompute in those cases.
    //
    // The file name is preserved for backward compatibility with older
    // on-disk state; a stale `has-local-sources` is harmless because it
    // only forces a slow freshness recompute until the next install
    // rewrites it.
    //
    // The string-search is conservative: false positives (a string
    // `"file:` appearing in a description or homepage URL, or a
    // `workspaces` field in a non-workspace tool config) bail the
    // fast path → still correct, just slightly slower. False
    // negatives are impossible for the file: / link: case: every
    // such spec is `"<key>": "file:..."` / `"<key>": "link:..."`.
    let sentinel = hash_dir.join("has-local-sources");
    let needs_slow_path = lpm_common::read_text_file_capped(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
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
/// Returns `Some(mode)` if the fast lane should attempt the check.
/// Returns `None` if any disqualifying flag or argument is present.
///
/// Recognized install subcommands: "install", "i" (visible_alias), and "ci"
/// (non-JSON only; `lpm ci --json` falls through to emit the full CI envelope).
///
/// Conservative: any unrecognized flag after "install" → fall through to
/// the full pipeline. This guarantees the fast lane never produces wrong
/// results — false negatives (falling through) are safe, false positives
/// (exiting early when we shouldn't) are not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FastLaneMode {
    pub json: bool,
    pub timing: bool,
    /// What `--frozen-lockfile` or `--no-frozen-lockfile` asked for, else
    /// frozen under CI. A frozen check also makes the checks a frozen
    /// install makes before it resolves.
    pub(crate) frozen_lockfile: crate::commands::install::FrozenLockfileMode,
    /// `--no-skills`: the install neither materializes package skills nor
    /// restores managed ones, so their state doesn't decide freshness.
    pub(crate) no_skills: bool,
    /// Raw `--min-release-age` argument forwarded to release-age validation.
    pub(crate) min_release_age: Option<String>,
    /// Raw `--min-release-age-exclude` arguments forwarded to release-age validation.
    pub(crate) min_release_age_exclude: Vec<String>,
    /// Explicit `--linker <hoisted|isolated>` override, if passed.
    pub(crate) linker: Option<lpm_linker::LinkerMode>,
    /// `--no-engine-strict`: skip fatal `engines` mismatches.
    pub(crate) no_engine_strict: bool,
}

pub fn argv_qualifies_for_fast_lane() -> Option<FastLaneMode> {
    // Use args_os() to avoid panicking on non-UTF-8 arguments.
    // Any argument that isn't valid UTF-8 causes a conservative bail
    // (fall through to the full pipeline where clap handles it).
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let args: Vec<&str> = raw_args
        .iter()
        .skip(1)
        .map(|a| a.to_str())
        .collect::<Option<Vec<_>>>()?;

    fast_lane_mode_from_args(&args)
}

fn fast_lane_mode_from_args(args: &[&str]) -> Option<FastLaneMode> {
    use crate::commands::install::FrozenLockfileMode;

    let mut json = false;
    let mut timing = false;
    let mut frozen_lockfile = None;
    let mut no_skills = false;
    let mut min_release_age: Option<String> = None;
    let mut min_release_age_exclude: Vec<String> = Vec::new();
    let mut linker: Option<lpm_linker::LinkerMode> = None;
    let mut no_engine_strict = false;
    let mut found_install = false;
    let mut is_ci = false;
    // clap refuses a non-repeatable flag given twice on one side of `install`,
    // so the fast lane must not answer for it.
    let mut seen: Vec<&str> = Vec::with_capacity(args.len());

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if found_install {
            if let Some(value) = arg.strip_prefix("--min-release-age=") {
                if min_release_age.is_some() {
                    return None;
                }
                min_release_age = Some(value.to_string());
                i += 1;
                continue;
            }
            if arg == "--min-release-age" {
                if min_release_age.is_some() {
                    return None;
                }
                let value = *args.get(i + 1)?;
                if value.starts_with('-') {
                    return None;
                }
                min_release_age = Some(value.to_string());
                i += 2;
                continue;
            }
            if let Some(value) = arg.strip_prefix("--min-release-age-exclude=") {
                min_release_age_exclude.push(value.to_string());
                i += 1;
                continue;
            }
            if arg == "--min-release-age-exclude" {
                let value = *args.get(i + 1)?;
                if value.starts_with('-') {
                    return None;
                }
                min_release_age_exclude.push(value.to_string());
                i += 2;
                continue;
            }
            if let Some(value) = arg.strip_prefix("--linker=") {
                if linker.is_some() {
                    return None;
                }
                linker = Some(lpm_linker::LinkerMode::parse_str(value).ok()?);
                i += 1;
                continue;
            }
            if arg == "--linker" {
                if linker.is_some() {
                    return None;
                }
                let value = *args.get(i + 1)?;
                if value.starts_with('-') {
                    return None;
                }
                linker = Some(lpm_linker::LinkerMode::parse_str(value).ok()?);
                i += 2;
                continue;
            }
        }
        if arg.starts_with('-') {
            if seen.contains(&arg) {
                return None;
            }
            seen.push(arg);
        }
        match arg {
            "--json" => json = true,
            "--timing" if found_install && !is_ci => timing = true,

            // Global flags that change registry/auth behavior → disqualify.
            // --token and --registry take a value: disqualify on the flag itself.
            "--token" | "--registry" => return None,
            _ if arg.starts_with("--token=") || arg.starts_with("--registry=") => return None,
            "--insecure" => return None,

            // Harmless global flags — skip. `-v` is clap's `--version`, not
            // this.
            "--verbose" => {}

            // The subcommand itself
            "install" | "i" if !found_install => {
                found_install = true;
                seen.clear();
            }
            "ci" if !found_install => {
                found_install = true;
                is_ci = true;
                frozen_lockfile = Some(FrozenLockfileMode::Always);
                seen.clear();
            }

            // Flags the check honours. Both frozen flags at once are left to
            // clap to refuse.
            "--frozen-lockfile" | "--no-frozen-lockfile" if found_install && !is_ci => {
                let mode = if arg == "--frozen-lockfile" {
                    FrozenLockfileMode::Always
                } else {
                    FrozenLockfileMode::Never
                };
                if frozen_lockfile
                    .replace(mode)
                    .is_some_and(|earlier| earlier != mode)
                {
                    return None;
                }
            }
            "--no-skills" if found_install => no_skills = true,
            "--no-engine-strict" if found_install => no_engine_strict = true,
            // An up-to-date install has no security summary or post-install audit to leave out.
            "--no-security-summary" | "--no-audit-after-install" if found_install => {}

            // Install-specific flags that disqualify the fast lane.
            // ANY of these means semantics differ from a bare `lpm install`.
            "--force" | "--offline" | "--filter" | "-w" | "--workspace-root"
            | "--fail-if-no-match" | "--allow-new" | "--exact" | "--tilde" | "--save-prefix"
            | "-D" | "--save-dev" | "--auto-build"
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
        i += 1;
    }

    if is_ci && json {
        return None;
    }

    found_install.then_some(FastLaneMode {
        json,
        timing,
        frozen_lockfile: frozen_lockfile.unwrap_or_default(),
        no_skills,
        min_release_age,
        min_release_age_exclude,
        linker,
        no_engine_strict,
    })
}

pub(crate) fn ci_env_is_truthy() -> bool {
    ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI"]
        .iter()
        .any(|key| {
            std::env::var(key).is_ok_and(|value| {
                let trimmed = value.trim();
                !trimmed.is_empty() && trimmed != "0" && !trimmed.eq_ignore_ascii_case("false")
            })
        })
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
    match lpm_common::read_text_file_capped(&pkg_json, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
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

    #[test]
    fn pnpm_workspace_yaml_declares_a_workspace_only_with_packages() {
        let root = tempfile::tempdir().unwrap();
        let member = root.path().join("apps/web");
        std::fs::create_dir_all(&member).unwrap();
        assert!(!pnpm_workspace_declares_packages(root.path()));

        let yaml = root.path().join("pnpm-workspace.yaml");
        std::fs::write(&yaml, "allowBuilds:\n  esbuild: true\n").unwrap();
        assert!(
            !pnpm_workspace_declares_packages(root.path()),
            "settings only"
        );

        std::fs::write(
            &yaml,
            "packages:\n  - apps/*\nallowBuilds:\n  esbuild: true\n",
        )
        .unwrap();
        assert!(pnpm_workspace_declares_packages(root.path()));
        assert!(
            pnpm_workspace_declares_packages(&member),
            "found from a member"
        );

        std::fs::write(&yaml, "packages: [unterminated\n").unwrap();
        assert!(
            pnpm_workspace_declares_packages(root.path()),
            "an unreadable file is left to workspace discovery to report"
        );
    }
    use std::fs;
    use tempfile::TempDir;

    fn scoped_home_for(_path: &Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::update([
            ("LPM_LINKER", None),
            (lpm_store::StoreVersion::ENV_VAR, None),
            (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
        ])
    }

    fn write_test_lockfile(project_dir: &Path) -> std::sync::Arc<str> {
        lpm_lockfile::Lockfile::default()
            .write_all(&project_dir.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        crate::commands::install::workspace_lockfile::active_lockfile_content(project_dir)
    }

    /// An install-hash file with `hash` and nothing else this release needs
    /// to trust it, as one from the slow path's point of view.
    fn current_hash_file(hash: &str) -> String {
        format!(
            "{hash}\ns:{}\nk:{}\nr:{}\n",
            lpm_linker::BIN_SHIM_FORMAT,
            lpm_store::v2::GraphKey::SCHEMA_VERSION,
            lpm_security::INSTALL_SCRIPT_RULES
        )
    }

    fn setup_up_to_date_project() -> TempDir {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        let lock = write_test_lockfile(p);
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash =
            compute_install_hash(&fs::read_to_string(p.join("package.json")).unwrap(), &lock);
        fs::write(
            p.join(".lpm").join("install-hash"),
            current_hash_file(&hash),
        )
        .unwrap();
        dir
    }

    #[test]
    fn fast_lane_mode_from_args_accepts_timing_after_install() {
        assert_eq!(
            fast_lane_mode_from_args(&["--json", "install", "--timing"]),
            Some(FastLaneMode {
                json: true,
                timing: true,
                frozen_lockfile: crate::commands::install::FrozenLockfileMode::Auto,
                no_skills: false,
                min_release_age: None,
                min_release_age_exclude: Vec::new(),
                linker: None,
                no_engine_strict: false,
            })
        );
    }

    #[test]
    fn fast_lane_mode_from_args_accepts_linker_no_audit_and_no_engine_strict() {
        use crate::commands::install::FrozenLockfileMode;

        assert_eq!(
            fast_lane_mode_from_args(&[
                "install",
                "--no-audit-after-install",
                "--no-engine-strict",
                "--linker",
                "hoisted",
            ]),
            Some(FastLaneMode {
                json: false,
                timing: false,
                frozen_lockfile: FrozenLockfileMode::Auto,
                no_skills: false,
                min_release_age: None,
                min_release_age_exclude: Vec::new(),
                linker: Some(lpm_linker::LinkerMode::Hoisted),
                no_engine_strict: true,
            })
        );
        assert_eq!(
            fast_lane_mode_from_args(&["ci", "--linker=isolated", "--no-audit-after-install"]),
            Some(FastLaneMode {
                json: false,
                timing: false,
                frozen_lockfile: FrozenLockfileMode::Always,
                no_skills: false,
                min_release_age: None,
                min_release_age_exclude: Vec::new(),
                linker: Some(lpm_linker::LinkerMode::Isolated),
                no_engine_strict: false,
            })
        );
        for rejected in [
            &["--linker=hoisted", "install"][..],
            &["install", "--linker"][..],
            &["install", "--linker", "--json"][..],
            &["install", "--linker=bogus"][..],
            &["install", "--linker", "hoisted", "--linker=isolated"][..],
            &[
                "install",
                "--no-audit-after-install",
                "--no-audit-after-install",
            ][..],
        ] {
            assert_eq!(
                fast_lane_mode_from_args(rejected),
                None,
                "rejected args should fall back to clap: {rejected:?}"
            );
        }
    }

    #[test]
    fn fast_lane_mode_from_args_handles_min_release_age_and_excludes() {
        use crate::commands::install::FrozenLockfileMode;

        assert_eq!(
            fast_lane_mode_from_args(&[
                "install",
                "--min-release-age=7d",
                "--min-release-age-exclude=lodash",
                "--min-release-age-exclude",
                "@types/*",
            ]),
            Some(FastLaneMode {
                json: false,
                timing: false,
                frozen_lockfile: FrozenLockfileMode::Auto,
                no_skills: false,
                min_release_age: Some("7d".to_string()),
                min_release_age_exclude: vec!["lodash".to_string(), "@types/*".to_string()],
                linker: None,
                no_engine_strict: false,
            })
        );
        assert_eq!(
            fast_lane_mode_from_args(&["ci", "--min-release-age", "3d"]),
            Some(FastLaneMode {
                json: false,
                timing: false,
                frozen_lockfile: FrozenLockfileMode::Always,
                no_skills: false,
                min_release_age: Some("3d".to_string()),
                min_release_age_exclude: Vec::new(),
                linker: None,
                no_engine_strict: false,
            })
        );
        // Duplicate --min-release-age, missing values, or flag before subcommand bail to clap.
        for rejected in [
            &["--min-release-age=7d", "install"][..],
            &["install", "--min-release-age"][..],
            &["install", "--min-release-age", "--json"][..],
            &["install", "--min-release-age=7d", "--min-release-age=3d"][..],
            &["install", "--min-release-age", "7d", "--min-release-age=3d"][..],
            &["install", "--min-release-age-exclude"][..],
            &["install", "--min-release-age-exclude", "--no-skills"][..],
            &["install", "--min-release-age=7d", "--allow-new"][..],
        ] {
            assert_eq!(fast_lane_mode_from_args(rejected), None, "{rejected:?}");
        }
    }

    #[test]
    fn fast_lane_mode_from_args_carries_the_frozen_lockfile_and_skills_flags() {
        use crate::commands::install::FrozenLockfileMode;

        let mode = |args: &[&str]| {
            fast_lane_mode_from_args(args).map(|mode| (mode.frozen_lockfile, mode.no_skills))
        };
        assert_eq!(
            mode(&["install", "--frozen-lockfile"]),
            Some((FrozenLockfileMode::Always, false))
        );
        assert_eq!(
            mode(&[
                "i",
                "--no-frozen-lockfile",
                "--no-skills",
                "--no-security-summary"
            ]),
            Some((FrozenLockfileMode::Never, true))
        );
        assert_eq!(
            mode(&["install", "--frozen-lockfile", "--no-frozen-lockfile"]),
            None
        );
        assert_eq!(mode(&["--frozen-lockfile", "install"]), None);
    }

    #[test]
    fn fast_lane_mode_from_args_leaves_a_repeated_flag_to_clap() {
        for args in [
            &["--json", "--json", "install"][..],
            &["--verbose", "--verbose", "install"][..],
            &["install", "--timing", "--timing"][..],
            &["install", "--frozen-lockfile", "--frozen-lockfile"][..],
            &["install", "--no-skills", "--no-skills"][..],
            &["install", "--no-security-summary", "--no-security-summary"][..],
        ] {
            assert_eq!(fast_lane_mode_from_args(args), None, "{args:?}");
        }
    }

    #[test]
    fn fast_lane_mode_from_args_accepts_a_global_flag_given_on_both_sides_of_install() {
        for args in [
            &["--json", "install", "--json"][..],
            &["--verbose", "install", "--verbose"][..],
        ] {
            assert!(fast_lane_mode_from_args(args).is_some(), "{args:?}");
        }
    }

    #[test]
    fn fast_lane_mode_from_args_leaves_the_version_flag_to_clap() {
        assert_eq!(fast_lane_mode_from_args(&["-v", "install"]), None);
        assert_eq!(fast_lane_mode_from_args(&["install", "-v"]), None);
    }

    #[test]
    fn fast_lane_mode_from_args_rejects_timing_before_install() {
        assert_eq!(fast_lane_mode_from_args(&["--timing", "install"]), None);
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
        // A malformed package.json with a forged matching install-hash must not
        // exit the fast lane with "success: true".
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
    fn install_hash_ignores_scripts_no_install_step_reads_and_formatting() {
        let hash = |manifest: &str| compute_install_hash(manifest, "lock");
        let base = hash(r#"{"name":"app","dependencies":{"a":"1.0.0"}}"#);

        for same in [
            r#"{"name":"app","dependencies":{"a":"1.0.0"},"scripts":{"dev":"vite"}}"#,
            "\u{feff}{\n  \"name\": \"app\",\n  \"dependencies\": { \"a\": \"1.0.0\" },\n  \"scripts\": {}\n}\n",
        ] {
            assert_eq!(hash(same), base, "{same}");
        }
        for different in [
            r#"{"name":"app","dependencies":{"a":"1.0.1"}}"#,
            r#"{"name":"app","dependencies":{"a":"1.0.0"},"scripts":{"postinstall":"node x"}}"#,
            r#"{"name":"app","dependencies":{"a":"1.0.0"},"scripts":{"pnpm:devPreinstall":"x"}}"#,
            r#"{"name":"app","dependencies":{"a":"1.0.0"},"scripts":"not an object"}"#,
            r#"{"dependencies":{"a":"1.0.0"},"name":"app"}"#,
        ] {
            assert_ne!(hash(different), base, "{different}");
        }
    }

    #[test]
    fn install_hash_reads_every_script_an_install_step_runs_or_blocks() {
        let hash = |manifest: String| compute_install_hash(&manifest, "lock");
        let base = hash(r#"{"name":"app"}"#.to_string());
        let phases = crate::commands::root_lifecycle::install_lifecycle_scripts()
            .chain(lpm_security::EXECUTED_INSTALL_PHASES.iter().copied())
            .chain([
                "preuninstall",
                "uninstall",
                "postuninstall",
                "prepublishOnly",
            ]);
        for phase in phases {
            assert_ne!(
                hash(format!(
                    r#"{{"name":"app","scripts":{{"{phase}":"node x"}}}}"#
                )),
                base,
                "{phase}"
            );
        }
    }

    #[test]
    fn local_dependency_manifests_count_whether_or_not_the_manifest_starts_with_a_byte_order_mark()
    {
        let dir = TempDir::new().unwrap();
        let local = dir.path().join("local");
        fs::create_dir_all(&local).unwrap();
        fs::write(
            local.join("package.json"),
            r#"{"name":"local","version":"1.0.0","dependencies":{"a":"1.0.0"}}"#,
        )
        .unwrap();
        let manifest = r#"{"name":"app","dependencies":{"local":"file:./local"}}"#;

        let plain = collect_file_link_manifest_bytes(dir.path(), manifest);
        let marked = collect_file_link_manifest_bytes(dir.path(), &format!("\u{feff}{manifest}"));

        assert!(!plain.is_empty());
        assert_eq!(marked, plain);
    }

    #[test]
    fn manifest_for_install_hash_ignores_the_dependency_skills_policy() {
        let without = br#"{"name":"app","dependencies":{"a":"1.0.0"}}"#;
        let with_policy =
            br##"{"name":"app","dependencies":{"a":"1.0.0"},"lpm":{"skills":{"allow":["#a"]}}}"##;
        let with_other_lpm =
            br##"{"name":"app","dependencies":{"a":"1.0.0"},"lpm":{"skills":{"allow":["#a"]},"linker":"hoisted"}}"##;

        assert_eq!(
            manifest_for_install_hash(without),
            manifest_for_install_hash(with_policy)
        );
        assert_ne!(
            manifest_for_install_hash(without),
            manifest_for_install_hash(with_other_lpm)
        );
        assert_eq!(
            manifest_for_install_hash(br#"{"name":"app","lpm":{}}"#).as_ref(),
            br#"{"name":"app","lpm":{}}"#
        );
    }

    #[test]
    fn manifest_for_install_hash_reads_non_json_content_as_written() {
        for content in [
            &b"packages:\n  - packages/*\n"[..],
            b"[1, 2]",
            b"\0not json",
        ] {
            assert_eq!(manifest_for_install_hash(content).as_ref(), content);
        }
    }

    #[test]
    fn schema_tag_is_baked_into_hash() {
        // Pin the hash of known inputs against the current schema tag so
        // that any accidental change to `INSTALL_HASH_SCHEMA_TAG` — or
        // removal of the `hasher.update(tag)` line — makes this test
        // fail loudly. The expected value below was computed from
        //   SHA256("lpm-install-hash-v8\x00" || "pkg" || "\x00" || "lock"
        //          || "\x00" || "\x00" || "isolated" || "\x00" || "source"
        //          || "\x00" || "linux/x64/glibc")
        // at the time the schema was bumped to v8.
        //
        // note: `compute_install_hash` now defaults
        // to `LinkerMode::default()` which flipped to Hoisted in 4f.
        // To keep this test schema-pinned (not coupled to whichever
        // linker or integrity policy is the default), call
        // `compute_install_hash_v8` explicitly with the values used at
        // the time the schema was last bumped. Updating this constant
        // is a deliberate act that must accompany any schema-version
        // bump.
        let platform = PlatformTuple::new("linux", "x64", Some("glibc".into()));
        let actual = compute_install_hash_v8(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
        );
        let expected_v8 = "b99f6a3fef74c29d25caab369921536fbc05c4a1691c4cdf5ba51c91106ea1cf";
        assert_eq!(
            actual, expected_v8,
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
            hex::encode(h.finalize())
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
        let lock = write_test_lockfile(p);
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let hash =
            compute_install_hash(&fs::read_to_string(p.join("package.json")).unwrap(), &lock);
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
    fn installed_project_is_up_to_date_without_a_binary_lockfile() {
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());

        assert!(check_install_state(dir.path()).up_to_date);
    }

    #[test]
    fn leftover_binary_lockfile_keeps_install_from_fast_lane_success() {
        let dir = setup_up_to_date_project_v2();
        let _home = scoped_home_for(dir.path());
        fs::write(
            dir.path().join(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME),
            b"LPMB leftover",
        )
        .unwrap();

        assert!(
            !check_install_state(dir.path()).up_to_date,
            "install must run so it can remove the leftover lpm.lockb"
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
    fn a_bare_hash_file_has_its_project_linked_again() {
        // A v1 install-hash file (bare 64-char hex) names neither the shim
        // format nor the store key schema its install linked with, so its
        // matching hash isn't enough.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        let lock = write_test_lockfile(p);
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash =
            compute_install_hash(&fs::read_to_string(p.join("package.json")).unwrap(), &lock);
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();
        assert!(!check_install_state(p).up_to_date);

        fs::write(
            p.join(".lpm").join("install-hash"),
            current_hash_file(&hash),
        )
        .unwrap();
        assert!(check_install_state(p).up_to_date);
    }

    #[test]
    fn write_install_hash_records_all_fast_path_metadata() {
        // Contract: file content is hash + mtime line + linker line + integrity line +
        // platform line + source-analysis line + dependency-engine line +
        // runtime fingerprint line + binary-sidecar expectation line.
        // Pins the on-disk format so a v1 reader still gets the hash on
        // line 1 (legacy compat), AND the mtime fast-path can detect
        // post-install config and platform flips without recomputing the full hash.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        lpm_lockfile::Lockfile::default()
            .write_to_file(&p.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
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
        let integrity_line = lines.next().unwrap();
        assert_eq!(
            integrity_line, "i:source",
            "expected integrity line `i:source`, got {integrity_line:?}"
        );
        let platform_line = lines.next().unwrap();
        assert!(
            platform_line.starts_with("p:"),
            "expected platform line, got {platform_line:?}"
        );
        assert_eq!(lines.next(), Some("a:disabled"));
        assert_eq!(lines.next(), Some("e:none"));
        assert_eq!(lines.next(), Some("n:none"));
        assert_eq!(
            lines.next(),
            Some(format!("s:{}", lpm_linker::BIN_SHIM_FORMAT).as_str())
        );
        assert_eq!(
            lines.next(),
            Some(format!("k:{}", lpm_store::v2::GraphKey::SCHEMA_VERSION).as_str())
        );
        assert_eq!(
            lines.next(),
            Some(format!("r:{}", lpm_security::INSTALL_SCRIPT_RULES).as_str())
        );
        assert_eq!(lines.next(), None);
    }

    /// A project linked before `.cmd` shims named their targets from
    /// `%dp0%` holds shims that break for a non-ASCII user folder, or none
    /// under a path with `'` or `&`; it isn't up to date until linked again.
    #[cfg(windows)]
    #[test]
    fn a_project_linked_with_older_windows_shims_is_not_up_to_date() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg = r#"{"dependencies":{}}"#;
        fs::write(p.join("package.json"), pkg).unwrap();
        lpm_lockfile::Lockfile::default()
            .write_to_file(&p.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let hash = check_install_state_with_content(p, pkg).hash.unwrap();
        write_install_hash(p, &hash, lpm_linker::LinkerMode::default()).unwrap();
        assert!(check_install_state_with_content(p, pkg).up_to_date);

        let hash_file = p.join(".lpm").join("install-hash");
        let older: String = fs::read_to_string(&hash_file)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("s:"))
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(&hash_file, older).unwrap();

        assert!(!check_install_state_with_content(p, pkg).up_to_date);
    }

    /// A project linked before a store key covered its packages' bytes may
    /// hold what another project installed; it isn't up to date until
    /// linked again, by either freshness check.
    #[test]
    fn a_project_linked_under_an_earlier_store_key_schema_is_not_up_to_date() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg = r#"{"dependencies":{}}"#;
        fs::write(p.join("package.json"), pkg).unwrap();
        lpm_lockfile::Lockfile::default()
            .write_to_file(&p.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let hash = check_install_state_with_content(p, pkg).hash.unwrap();
        write_install_hash(p, &hash, lpm_linker::LinkerMode::default()).unwrap();
        assert!(check_install_state_with_content(p, pkg).up_to_date);
        assert!(check_install_state(p).up_to_date);

        let hash_file = p.join(".lpm").join("install-hash");
        let written = fs::read_to_string(&hash_file).unwrap();
        for earlier in ["", "k:5\n"] {
            let older: String = written
                .lines()
                .filter(|line| !line.starts_with("k:"))
                .map(|line| format!("{line}\n"))
                .chain([earlier.to_owned()])
                .collect();
            fs::write(&hash_file, older).unwrap();

            assert!(!check_install_state_with_content(p, pkg).up_to_date);
            assert!(!check_install_state(p).up_to_date);
        }
    }

    #[test]
    fn a_project_installed_under_earlier_install_script_rules_is_not_up_to_date() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        let pkg = r#"{"dependencies":{}}"#;
        fs::write(p.join("package.json"), pkg).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let hash = check_install_state_with_content(p, pkg).hash.unwrap();
        write_install_hash(p, &hash, lpm_linker::LinkerMode::default()).unwrap();
        assert!(check_install_state_with_content(p, pkg).up_to_date);

        let hash_file = p.join(".lpm").join("install-hash");
        let written = fs::read_to_string(&hash_file).unwrap();
        for earlier in ["", "r:1\n"] {
            let older: String = written
                .lines()
                .filter(|line| !line.starts_with("r:"))
                .map(|line| format!("{line}\n"))
                .chain([earlier.to_owned()])
                .collect();
            fs::write(&hash_file, older).unwrap();

            assert!(!check_install_state_with_content(p, pkg).up_to_date);
            assert!(!check_install_state(p).up_to_date);
        }
    }

    #[test]
    fn install_hash_reserves_node_runtime_fingerprint_metadata() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();

        write_install_hash(p, "abc123", lpm_linker::LinkerMode::Hoisted).unwrap();

        let content = fs::read_to_string(p.join(".lpm").join("install-hash")).unwrap();
        assert!(
            content.lines().any(|line| line == "n:none"),
            "install-hash must reserve a stable node runtime fingerprint line: {content:?}"
        );
    }

    #[test]
    fn runtime_fingerprint_refresh_preserves_other_install_state_metadata() {
        const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        let platform = PlatformTuple::current();
        write_install_hash_with_integrity_platform_and_dependency_engine(
            p,
            "abc123",
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
            "1:22.0.0",
            Some(OLD),
        )
        .unwrap();
        let path = p.join(".lpm").join("install-hash");
        let before = fs::read_to_string(&path).unwrap();
        let expected = before.replace(&format!("n:{OLD}"), &format!("n:{NEW}"));

        let refreshed =
            refresh_install_hash_node_runtime_fingerprint(p, "1:22.0.0", Some(NEW)).unwrap();

        assert!(refreshed);
        assert_eq!(fs::read_to_string(path).unwrap(), expected);
    }

    #[test]
    fn runtime_fingerprint_refresh_appends_missing_metadata() {
        const FINGERPRINT: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let legacy = "hash\nm:1:2\nl:hoisted\ni:source\np:linux/x64/glibc\ne:1:22.0.0\n";

        let updated =
            replace_node_runtime_fingerprint(legacy, "1:22.0.0", Some(FINGERPRINT)).unwrap();

        assert_eq!(updated, format!("{legacy}n:{FINGERPRINT}\n"));
    }

    #[test]
    fn runtime_fingerprint_refresh_rejects_changed_engine_key() {
        const FINGERPRINT: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let state = "hash\nm:1:2\nl:hoisted\ni:source\np:linux/x64/glibc\ne:1:23.0.0\nn:none\n";

        assert!(replace_node_runtime_fingerprint(state, "1:22.0.0", Some(FINGERPRINT)).is_none());
    }

    #[test]
    fn unconstrained_dependency_engine_context_preserves_v8_hash() {
        let platform = PlatformTuple::new("linux", "x64", Some("glibc".into()));
        let v8 = compute_install_hash_v8(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
        );
        let v9 = compute_install_hash_v9(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
            "none",
        );

        assert_eq!(v9, v8);
    }

    #[test]
    fn constrained_dependency_engine_context_changes_with_runtime_or_strictness() {
        let platform = PlatformTuple::new("linux", "x64", Some("glibc".into()));
        let hash_for = |dependency_engine_key| {
            compute_install_hash_v9(
                "pkg",
                "lock",
                &[],
                lpm_linker::LinkerMode::Isolated,
                ObjectIntegrityPolicy::Source,
                &platform,
                dependency_engine_key,
            )
        };

        let strict_node_22 = hash_for("1:22.0.0");
        assert_ne!(strict_node_22, hash_for("1:20.0.0"));
        assert_ne!(strict_node_22, hash_for("0:22.0.0"));
    }

    #[test]
    fn write_install_hash_records_current_platform_tuple() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let _home = scoped_home_for(p);
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();

        write_install_hash(p, "abc123", lpm_linker::LinkerMode::Hoisted).unwrap();

        let content = fs::read_to_string(p.join(".lpm").join("install-hash")).unwrap();
        let expected = format!("p:{}", platform_tuple_key(&PlatformTuple::current()));
        let platform_line = content
            .lines()
            .nth(4)
            .expect("install-hash must include a platform tuple line");
        assert_eq!(
            platform_line, expected,
            "install-hash must record the current host platform tuple"
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
    fn state_publication_replaces_complete_content_without_leaving_temporary_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("install-hash");
        write_state_file_owner_only(&path, b"previous complete state").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"previous complete state");
        let replacement = vec![b'x'; 8192];
        write_state_file_owner_only(&path, &replacement).unwrap();
        assert_eq!(fs::read(&path).unwrap(), replacement);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn state_publication_replaces_the_file_without_mutating_open_readers() {
        use std::io::Read;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("install-hash");
        write_state_file_owner_only(&path, b"previous complete state").unwrap();
        let mut previous = fs::File::open(&path).unwrap();
        let replacement = vec![b'x'; 8192];
        write_state_file_owner_only(&path, &replacement).unwrap();
        let mut retained = Vec::new();
        previous.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, b"previous complete state");
        assert_eq!(fs::read(&path).unwrap(), replacement);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn absent_or_invalid_state_cache_requires_install_validation() {
        let dir = setup_up_to_date_project_v2();
        let project = dir.path();
        let _home = scoped_home_for(project);
        assert!(check_install_state(project).up_to_date);
        let path = project.join(".lpm/install-hash");
        let saved = fs::read(&path).unwrap();
        for content in [b"".as_slice(), b"\xff", &saved[..8]] {
            write_state_file_owner_only(&path, content).unwrap();
            assert!(!check_install_state(project).up_to_date);
        }
        fs::remove_file(path).unwrap();
        assert!(!check_install_state(project).up_to_date);
    }

    #[test]
    fn local_source_sentinel_is_published_empty_and_removed_when_unneeded() {
        let dir = TempDir::new().unwrap();
        let project = dir.path();
        fs::write(
            project.join("package.json"),
            r#"{"dependencies":{"local":"file:../local"}}"#,
        )
        .unwrap();
        fs::write(project.join("lpm.lock"), "").unwrap();
        write_install_hash(project, "hash", lpm_linker::LinkerMode::Isolated).unwrap();
        let sentinel = project.join(".lpm/has-local-sources");
        assert_eq!(fs::read(&sentinel).unwrap(), b"");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&sentinel).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(project.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        write_install_hash(project, "hash", lpm_linker::LinkerMode::Isolated).unwrap();
        assert!(!sentinel.exists());
    }

    #[test]
    fn unchanged_runtime_fingerprint_does_not_republish_the_state_file() {
        let dir = TempDir::new().unwrap();
        let project = dir.path();
        fs::create_dir(project.join(".lpm")).unwrap();
        let path = project.join(".lpm/install-hash");
        let fingerprint = "a".repeat(64);
        let original = format!("hash\ne:1:22.0.0\nn:{fingerprint}\n");
        write_state_file_owner_only(&path, original.as_bytes()).unwrap();
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1234);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(
            !refresh_install_hash_node_runtime_fingerprint(project, "1:22.0.0", Some(&fingerprint))
                .unwrap()
        );
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), old);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(!refresh_install_hash_node_runtime_fingerprint(project, "1:23.0.0", None).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), old);
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
    fn integrity_policy_folds_into_install_hash() {
        let platform = PlatformTuple::new("linux", "x64", Some("glibc".into()));
        let source = compute_install_hash_v8(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
        );
        let tree = compute_install_hash_v8(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Tree,
            &platform,
        );
        assert_ne!(
            source, tree,
            "v8 must distinguish object integrity policies so a source/tree config flip \
             cannot reuse the prior install freshness state"
        );
    }

    #[test]
    fn source_analysis_policy_folds_into_install_hash() {
        let platform = PlatformTuple::current();
        let enabled = compute_install_hash_v10(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
            InstallHashContext {
                security_analysis_policy: SecurityAnalysisPolicy::Enabled,
                ..InstallHashContext::default()
            },
        );
        let disabled = compute_install_hash_v10(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
            InstallHashContext {
                dependency_engine_key: "none",
                security_analysis_policy: SecurityAnalysisPolicy::Disabled,
            },
        );

        assert_ne!(enabled, disabled);
    }

    #[test]
    fn platform_tuple_folds_into_install_hash() {
        let glibc = PlatformTuple::new("linux", "x64", Some("glibc".into()));
        let musl = PlatformTuple::new("linux", "x64", Some("musl".into()));
        let glibc_hash = compute_install_hash_v8(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &glibc,
        );
        let musl_hash = compute_install_hash_v8(
            "pkg",
            "lock",
            &[],
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &musl,
        );
        assert_ne!(
            glibc_hash, musl_hash,
            "v8 must distinguish host libc so a glibc/musl cache move reruns install filtering"
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
        let platform = PlatformTuple::current();
        let same = try_mtime_fast_path(
            FreshnessPaths {
                project_dir: p,
                lockfile: None,
            },
            &pkg_content,
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
            lpm_store::StoreVersion::V2,
            InstallHashContext::default(),
        );
        assert!(
            same.is_some_and(|s| s.up_to_date),
            "matching linker should keep up_to_date=true on the fast path"
        );
        // Mtime fast path with FLIPPED linker → bails (returns None).
        let flipped = try_mtime_fast_path(
            FreshnessPaths {
                project_dir: p,
                lockfile: None,
            },
            &pkg_content,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
            lpm_store::StoreVersion::V2,
            InstallHashContext::default(),
        );
        assert!(
            flipped.is_none(),
            "stored linker `isolated` must NOT short-circuit a check \
             resolving to `hoisted`; the freshness gate is load-bearing \
             for env/config-driven layout flips"
        );
    }

    #[test]
    fn mtime_fast_path_bails_when_stored_platform_differs() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();

        let content = format!(
            "deadbeef\nm:{}:{}\nl:hoisted\ni:source\np:alien/ghost/unknown\n",
            mtime_ns(&p.join("package.json")).unwrap(),
            mtime_ns(&p.join("lpm.lock")).unwrap()
        );
        fs::write(p.join(".lpm").join("install-hash"), content).unwrap();

        let pkg_content = fs::read_to_string(p.join("package.json")).unwrap();
        let fast = try_mtime_fast_path(
            FreshnessPaths {
                project_dir: p,
                lockfile: None,
            },
            &pkg_content,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &PlatformTuple::current(),
            lpm_store::StoreVersion::V2,
            InstallHashContext::default(),
        );
        assert!(
            fast.is_none(),
            "stored platform tuple must not short-circuit a check running on a different host"
        );
    }

    #[test]
    fn mtime_fast_path_bails_when_dependency_engine_context_differs() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let platform = PlatformTuple::current();
        write_install_hash_with_integrity_platform_and_dependency_engine(
            p,
            "deadbeef",
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
            "1:22.0.0",
            None,
        )
        .unwrap();

        let pkg_content = fs::read_to_string(p.join("package.json")).unwrap();
        let fast = try_mtime_fast_path(
            FreshnessPaths {
                project_dir: p,
                lockfile: None,
            },
            &pkg_content,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
            lpm_store::StoreVersion::V2,
            InstallHashContext {
                dependency_engine_key: "1:20.0.0",
                security_analysis_policy:
                    crate::source_analysis_config::DEFAULT_SECURITY_ANALYSIS_POLICY,
            },
        );

        assert!(fast.is_none());
    }

    #[test]
    fn integrity_policy_flip_invalidates_matching_install_state() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let package_json = r#"{"dependencies":{"a":"^1.0.0"}}"#;
        let lock = "lock-content";
        fs::write(p.join("package.json"), package_json).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();

        let platform = PlatformTuple::current();
        let source_hash = compute_install_hash_v8(
            package_json,
            lock,
            &[],
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
        );
        write_install_hash_with_integrity_and_platform(
            p,
            &source_hash,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            &platform,
        )
        .unwrap();

        let source_state = check_install_state_with_linker_and_integrity(
            p,
            package_json,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
        );
        assert!(
            source_state.up_to_date,
            "matching source policy should keep the install state warm"
        );

        let tree_state = check_install_state_with_linker_and_integrity(
            p,
            package_json,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Tree,
        );
        assert!(
            !tree_state.up_to_date,
            "switching to tree integrity must force the install pipeline to run"
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
        let lock = write_test_lockfile(p);
        fs::create_dir_all(p.join("node_modules")).unwrap();

        // Compute and write the v3 hash AS THE INSTALL PIPELINE
        // WOULD (with file/link bytes folded in).
        let bytes = collect_file_link_manifest_bytes(p, pkg);
        let initial_hash = compute_install_hash_v3(pkg, &lock, &bytes);
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
        let lock = write_test_lockfile(p);
        fs::create_dir_all(p.join("node_modules")).unwrap();
        // Empty `.lpm/` dir created before hash write.
        fs::create_dir_all(p.join("node_modules/.lpm")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(pkg_json, &lock);
        fs::write(
            p.join(".lpm").join("install-hash"),
            current_hash_file(&hash),
        )
        .unwrap();

        let state = check_install_state(p);
        assert!(state.up_to_date, "empty legacy dir must not gate install");
    }

    /// Populated v1 wrapper state is stale whenever a virtual-store version is
    /// selected, even if the manifest and lockfile hash still match.
    #[test]
    fn populated_v1_wrappers_force_virtual_store_migration_on_default() {
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
            "v1 wrappers under the virtual-store default must trigger migration"
        );
    }

    #[test]
    fn selected_store_version_controls_v1_layout_migration_without_rereading_environment() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let pkg_json = r#"{"dependencies":{"a":"^1.0.0"}}"#;
        fs::write(p.join("package.json"), pkg_json).unwrap();
        let lock = write_test_lockfile(p);
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm/hoisted")).unwrap();
        let hash = compute_install_hash(pkg_json, &lock);
        fs::write(p.join(".lpm/install-hash"), current_hash_file(&hash)).unwrap();

        let v1 = check_install_state_with_linker_integrity_and_dependency_engine(
            p,
            pkg_json,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            "none",
            lpm_store::StoreVersion::V1,
        );
        let v2 = check_install_state_with_linker_integrity_and_dependency_engine(
            p,
            pkg_json,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            "none",
            lpm_store::StoreVersion::V2,
        );
        let v3 = check_install_state_with_linker_integrity_and_dependency_engine(
            p,
            pkg_json,
            lpm_linker::LinkerMode::Hoisted,
            ObjectIntegrityPolicy::Source,
            "none",
            lpm_store::StoreVersion::V3,
        );

        assert_eq!(v1.hash.as_deref(), Some(hash.as_str()));
        assert!(v1.up_to_date, "explicit v1 keeps its rollback layout valid");
        assert!(!v2.up_to_date, "v2 must migrate the same legacy v1 layout");
        assert!(!v3.up_to_date, "v3 must migrate the same legacy v1 layout");
    }

    #[cfg(unix)]
    #[test]
    fn selected_virtual_store_version_invalidates_links_to_the_other_store() {
        let dir = TempDir::new().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        let _home =
            crate::test_env::ScopedEnv::set([("LPM_HOME", lpm_home.as_os_str().to_owned())]);
        let lpm_root = lpm_common::LpmRoot::from_dir(&lpm_home);

        for (actual, selected, project_name) in [
            (
                lpm_store::StoreVersion::V3,
                lpm_store::StoreVersion::V2,
                "v3-to-v2",
            ),
            (
                lpm_store::StoreVersion::V2,
                lpm_store::StoreVersion::V3,
                "v2-to-v3",
            ),
        ] {
            let project = dir.path().join(project_name);
            let package_json = r#"{"dependencies":{"a":"^1.0.0"}}"#;
            fs::create_dir_all(project.join("node_modules")).unwrap();
            fs::create_dir_all(project.join(".lpm")).unwrap();
            fs::write(project.join("package.json"), package_json).unwrap();
            let lock = write_test_lockfile(&project);

            let store = lpm_store::v2::Store::from_lpm_root_for_version(&lpm_root, actual);
            let target = store.paths().links_root().join("entry/node_modules/a");
            fs::create_dir_all(&target).unwrap();
            std::os::unix::fs::symlink(&target, project.join("node_modules/a")).unwrap();

            let hash = compute_install_hash(package_json, &lock);
            write_install_hash(&project, &hash, lpm_linker::LinkerMode::Isolated).unwrap();

            let state = check_install_state_with_linker_integrity_and_dependency_engine(
                &project,
                package_json,
                lpm_linker::LinkerMode::Isolated,
                ObjectIntegrityPolicy::Source,
                "none",
                selected,
            );

            assert!(
                !state.up_to_date,
                "selecting {selected} must relink a project that still points into {actual}"
            );
        }
    }

    #[test]
    fn ci_subcommand_qualifies_for_frozen_sync_fast_lane_without_install_only_flags() {
        use crate::commands::install::FrozenLockfileMode;

        assert_eq!(
            fast_lane_mode_from_args(&["ci"]),
            Some(FastLaneMode {
                json: false,
                timing: false,
                frozen_lockfile: FrozenLockfileMode::Always,
                no_skills: false,
                min_release_age: None,
                min_release_age_exclude: Vec::new(),
                linker: None,
                no_engine_strict: false,
            })
        );
        assert_eq!(
            fast_lane_mode_from_args(&["ci", "--no-skills", "--no-security-summary"]),
            Some(FastLaneMode {
                json: false,
                timing: false,
                frozen_lockfile: FrozenLockfileMode::Always,
                no_skills: true,
                min_release_age: None,
                min_release_age_exclude: Vec::new(),
                linker: None,
                no_engine_strict: false,
            })
        );
        // `lpm ci --json` must fall through to emit the full JSON envelope.
        assert_eq!(
            fast_lane_mode_from_args(&["--json", "ci", "--no-skills", "--no-security-summary"]),
            None
        );
        assert_eq!(fast_lane_mode_from_args(&["ci", "--timing"]), None);
        assert_eq!(fast_lane_mode_from_args(&["ci", "--frozen-lockfile"]), None);
        assert_eq!(
            fast_lane_mode_from_args(&["ci", "--no-frozen-lockfile"]),
            None
        );
    }

    #[test]
    fn sync_noop_proof_line_round_trips_and_rejects_malformed_entries() {
        let pkg_digest = sync_noop_content_digest_hex(b"{\"name\":\"app\"}");
        let lock_digest = sync_noop_content_digest_hex(b"[metadata]\nlockfile-version = 10\n");
        let input = SyncNoopLockfileProofInput {
            pkg_digest: pkg_digest.clone(),
            lock_digest: lock_digest.clone(),
            lockfile_eligible: true,
            has_node_engines: true,
            auto_install_peers: false,
            frozen_ok: true,
            routes_fingerprint: "0123456789abcdef".to_string(),
            pkg_stamp: Some(SyncNoopFileStamp {
                len: 14,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: 1_700_000_000_000_000_000,
                dev: 7,
                ino: 42,
            }),
            lock_stamp: Some(SyncNoopFileStamp {
                len: 128,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: 1_700_000_000_000_000_000,
                dev: 7,
                ino: 43,
            }),
        };
        let proof = SyncNoopLockfileProof::from_input(&input);
        let state = format!("hash\nf:{}\n", proof.format_line_value());
        assert_eq!(SyncNoopLockfileProof::parse_from_state(&state), Some(proof));

        // Legacy v2 proofs without file stamps continue to parse cleanly.
        let v = lpm_lockfile::LOCKFILE_VERSION;
        let legacy_v2 = format!("hash\nf:v2:{v}:{pkg_digest}:{lock_digest}:0b:0123456789abcdef\n");
        let parsed_v2 =
            SyncNoopLockfileProof::parse_from_state(&legacy_v2).expect("v2 proof must still parse");
        assert_eq!(parsed_v2.pkg_stamp, None);
        assert_eq!(parsed_v2.lock_stamp, None);
        let wrong_version = format!(
            "hash\nf:v2:{}:{pkg_digest}:{lock_digest}:0b:0123456789abcdef\n",
            v + 1
        );
        let unknown_flags =
            format!("hash\nf:v2:{v}:{pkg_digest}:{lock_digest}:1b:0123456789abcdef\n");
        let short_routes = format!("hash\nf:v2:{v}:{pkg_digest}:{lock_digest}:0b:short\n");
        let upper_routes =
            format!("hash\nf:v2:{v}:{pkg_digest}:{lock_digest}:0b:0123456789ABCDEF\n");
        let dup_line = format!(
            "hash\nf:v2:{v}:{pkg_digest}:{lock_digest}:0b:0123456789abcdef\nf:v2:{v}:{pkg_digest}:{lock_digest}:0b:0123456789abcdef\n"
        );
        for malformed in [
            "hash\nf:v1:128:4096:0b:0123456789abcdef\n",
            wrong_version.as_str(),
            unknown_flags.as_str(),
            short_routes.as_str(),
            upper_routes.as_str(),
            dup_line.as_str(),
        ] {
            assert_eq!(
                SyncNoopLockfileProof::parse_from_state(malformed),
                None,
                "malformed proof must be ignored: {malformed:?}"
            );
        }
    }

    #[test]
    fn descriptor_stamp_rejects_fd_vs_path_identity_mismatch_and_symlinked_files() {
        let fd_stamp = SyncNoopFileStamp {
            len: 32,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: 1_700_000_000_000_000_000,
            dev: 1,
            ino: 100,
        };
        let other_ino = SyncNoopFileStamp {
            ino: 101,
            ..fd_stamp
        };
        let other_dev = SyncNoopFileStamp { dev: 2, ..fd_stamp };
        assert_eq!(
            verified_descriptor_stamp(Some(fd_stamp), Some(fd_stamp), Some(fd_stamp), 32),
            Some(fd_stamp)
        );
        assert_eq!(
            verified_descriptor_stamp(Some(fd_stamp), Some(fd_stamp), Some(other_ino), 32),
            None,
            "path inode mismatch against the opened descriptor must drop the stamp"
        );
        assert_eq!(
            verified_descriptor_stamp(Some(fd_stamp), Some(other_dev), Some(fd_stamp), 32),
            None,
            "post-read descriptor change must drop the stamp"
        );
        assert_eq!(
            verified_descriptor_stamp(Some(fd_stamp), Some(fd_stamp), Some(fd_stamp), 31),
            None,
            "byte length mismatch must drop the stamp"
        );

        #[cfg(unix)]
        {
            let dir = TempDir::new().unwrap();
            let real = dir.path().join("real.json");
            let link = dir.path().join("link.json");
            fs::write(&real, br#"{"name":"linked"}"#).unwrap();
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let (bytes, stamp) =
                read_regular_file_capped_with_stamp(&link, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                    .unwrap();
            assert_eq!(bytes, br#"{"name":"linked"}"#);
            assert_eq!(
                stamp, None,
                "symlinked file must remain readable without receiving a regular-file stamp"
            );
        }
    }

    #[tokio::test]
    async fn cached_workspace_freshness_snapshot_matches_uncached_file_link_manifest_bytes() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fs::write(
            root.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"],"scripts":{"dev":"vite"}}"#,
        )
        .unwrap();
        let member_a = root.join("packages/a");
        let member_b = root.join("packages/b");
        let external = root.join("vendor-local");
        fs::create_dir_all(&member_a).unwrap();
        fs::create_dir_all(&member_b).unwrap();
        fs::create_dir_all(&external).unwrap();

        let pkg_a = r#"{"name":"a","version":"1.0.0","scripts":{"build":"tsc"}}"#;
        let pkg_b = r#"{"name":"b","version":"1.0.0","dependencies":{"vendor-local":"file:../../vendor-local","a":"file:../a"}}"#;
        fs::write(member_a.join("package.json"), pkg_a).unwrap();
        fs::write(member_b.join("package.json"), pkg_b).unwrap();
        fs::write(
            external.join("package.json"),
            r#"{"name":"vendor-local","version":"0.1.0","scripts":{"test":"vitest"}}"#,
        )
        .unwrap();

        let uncached_a = collect_file_link_manifest_bytes(&member_a, pkg_a);
        let uncached_b = collect_file_link_manifest_bytes(&member_b, pkg_b);

        let workspace =
            std::sync::Arc::new(lpm_workspace::discover_workspace(root).unwrap().unwrap());
        let freshness_cache = std::sync::Arc::new(
            crate::workspace_discovery_cache::WorkspaceFreshnessCache::default(),
        );

        crate::workspace_discovery_cache::scope(workspace, None, freshness_cache, async {
            let shared_a = collect_file_link_manifest_bytes_shared(&member_a, pkg_a);
            assert!(
                matches!(shared_a, FileLinkManifestBytes::Shared(_)),
                "member without file:/link: specs must borrow the cached workspace snapshot"
            );
            assert_eq!(shared_a.as_ref(), uncached_a.as_slice());

            let shared_b = collect_file_link_manifest_bytes_shared(&member_b, pkg_b);
            assert_eq!(shared_b.as_ref(), uncached_b.as_slice());
        })
        .await;
    }

    #[test]
    fn sync_noop_stamp_rejects_future_wall_clock_for_same_tick_healing() {
        let future_mtime = SyncNoopFileStamp {
            len: 16,
            mtime_ns: 2_000,
            ctime_ns: 1_000,
            dev: 1,
            ino: 10,
        };
        assert!(!future_mtime.is_strictly_older_than_wall_clock(1_500));
        assert!(!future_mtime.is_strictly_older_than_wall_clock(2_000));
        assert!(future_mtime.is_strictly_older_than_wall_clock(2_001));

        #[cfg(unix)]
        {
            let future_ctime = SyncNoopFileStamp {
                len: 16,
                mtime_ns: 1_000,
                ctime_ns: 2_000,
                dev: 1,
                ino: 10,
            };
            assert!(!future_ctime.is_strictly_older_than_wall_clock(1_500));
            assert!(!future_ctime.is_strictly_older_than_wall_clock(2_000));
            assert!(future_ctime.is_strictly_older_than_wall_clock(2_001));
        }
    }

    #[test]
    fn backfill_install_hash_sync_noop_proof_aborts_when_header_changed_concurrently() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".lpm")).unwrap();
        let hash_path = root.join(".lpm/install-hash");
        let original = "hash_a\nm:100:200\n";
        fs::write(&hash_path, original).unwrap();
        let (_, real_stamp) = read_text_regular_file_capped_with_stamp(
            &hash_path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
        )
        .unwrap();

        let input = SyncNoopLockfileProofInput {
            pkg_digest: sync_noop_content_digest_hex(b"{}"),
            lock_digest: sync_noop_content_digest_hex(b""),
            lockfile_eligible: true,
            has_node_engines: false,
            auto_install_peers: false,
            frozen_ok: true,
            routes_fingerprint: "0123456789abcdef".to_string(),
            pkg_stamp: None,
            lock_stamp: None,
        };

        let stale_hash = backfill_install_hash_sync_noop_proof_with_refresh(
            root,
            &input,
            true,
            Some(("hash_other", "m:100:200", real_stamp)),
        )
        .unwrap();
        assert!(!stale_hash, "hash line mismatch must abort backfill");
        assert_eq!(fs::read_to_string(&hash_path).unwrap(), original);

        let wrong_stamp = SyncNoopFileStamp {
            len: 999,
            mtime_ns: 1,
            ctime_ns: 1,
            dev: 1,
            ino: 1,
        };
        let stale_stamp = backfill_install_hash_sync_noop_proof_with_refresh(
            root,
            &input,
            true,
            Some(("hash_a", "m:100:200", Some(wrong_stamp))),
        )
        .unwrap();
        assert!(!stale_stamp, "stamp mismatch must abort backfill");
        assert_eq!(fs::read_to_string(&hash_path).unwrap(), original);

        let applied = backfill_install_hash_sync_noop_proof_with_refresh(
            root,
            &input,
            true,
            Some(("hash_a", "m:100:200", real_stamp)),
        )
        .unwrap();
        assert!(applied, "matching header and stamp must allow backfill");
        assert!(
            SyncNoopLockfileProof::parse_from_state(&fs::read_to_string(&hash_path).unwrap())
                .is_some()
        );
    }

    #[test]
    fn check_install_state_with_lockfile_detects_same_mtime_lockfile_edit() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let pkg = r#"{"name":"app","version":"1.0.0"}"#;
        fs::write(root.join("package.json"), pkg).unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();

        let original_lock = lpm_lockfile::Lockfile::new();
        let original_toml = original_lock.to_toml().unwrap();
        let lock_path = root.join(lpm_lockfile::LOCKFILE_NAME);
        fs::write(&lock_path, &original_toml).unwrap();
        let original_mtime = fs::metadata(&lock_path).unwrap().modified().unwrap();

        let hash_context = InstallHashContext {
            dependency_engine_key: "none",
            security_analysis_policy: lpm_store::SecurityAnalysisPolicy::Disabled,
        };
        let platform = PlatformTuple::current();
        let original_hash = compute_install_hash_v10(
            pkg,
            &original_toml,
            &[],
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
            hash_context,
        );
        write_install_hash_with_known_runtime_state(
            root,
            &original_hash,
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
            hash_context.dependency_engine_key,
            KnownInstallHashRuntimeState {
                lockfile_path: &lock_path,
                node_runtime_fingerprint: None,
                security_analysis_policy: hash_context.security_analysis_policy,
                sync_noop_proof: None,
                release_age_policy_key: None,
            },
        )
        .unwrap();

        let mut edited_lock = lpm_lockfile::Lockfile::new();
        edited_lock.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([(
                    "left-pad".to_string(),
                    "1.3.0".to_string(),
                )]),
                ..Default::default()
            },
        );
        let edited_toml = edited_lock.to_toml().unwrap();
        fs::write(&lock_path, &edited_toml).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let loaded = lpm_lockfile::ProjectLockfile {
            path: lock_path,
            importer: ".".to_string(),
            content: edited_toml,
            lockfile: edited_lock,
            workspace_root: None,
        };
        let state = check_install_state_with_lockfile(
            root,
            pkg,
            &loaded,
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            lpm_store::StoreVersion::V2,
            hash_context,
        );
        assert!(
            !state.up_to_date,
            "explicitly loaded lockfile check must verify content hash even when mtime is unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_regular_file_capped_with_stamp_rejects_symlink_to_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("manifest.fifo");
        let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let link = dir.path().join("package.json");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();

        let result =
            read_regular_file_capped_with_stamp(&link, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES);
        assert!(
            result.is_err(),
            "symlink to FIFO must fail immediately instead of blocking"
        );
    }

    #[test]
    fn backfill_install_hash_sync_noop_proof_skips_when_project_install_lock_is_held() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".lpm")).unwrap();
        let hash_path = root.join(".lpm/install-hash");
        let original = "hash_a\nm:100:200\n";
        fs::write(&hash_path, original).unwrap();
        let (_, real_stamp) = read_text_regular_file_capped_with_stamp(
            &hash_path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
        )
        .unwrap();

        let lock_path = lpm_common::project_install_lock(root);
        let _install_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();

        let input = SyncNoopLockfileProofInput {
            pkg_digest: sync_noop_content_digest_hex(b"{}"),
            lock_digest: sync_noop_content_digest_hex(b""),
            lockfile_eligible: true,
            has_node_engines: false,
            auto_install_peers: false,
            frozen_ok: true,
            routes_fingerprint: "0123456789abcdef".to_string(),
            pkg_stamp: None,
            lock_stamp: None,
        };
        let applied = backfill_install_hash_sync_noop_proof_with_refresh(
            root,
            &input,
            true,
            Some(("hash_a", "m:100:200", real_stamp)),
        )
        .unwrap();
        assert!(
            !applied,
            "proof backfill must skip when another install holds the project install lock"
        );
        assert_eq!(fs::read_to_string(&hash_path).unwrap(), original);
    }

    #[test]
    fn malformed_verified_stamp_line_rejects_mtime_fast_path_while_absent_stays_compatible() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let pkg_path = root.join("package.json");
        let lock_path = root.join("lpm.lock");
        let pkg = r#"{"name":"stamp-parse","version":"1.0.0"}"#;
        fs::write(&pkg_path, pkg).unwrap();
        fs::write(&lock_path, "lockfile_version = 13\n").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::create_dir_all(root.join(".lpm")).unwrap();

        let pkg_stamp = read_text_regular_file_capped_with_stamp(
            &pkg_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .unwrap()
        .1
        .expect("package.json stamp");
        let lock_stamp = read_text_regular_file_capped_with_stamp(
            &lock_path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
        )
        .unwrap()
        .1
        .expect("lpm.lock stamp");
        let hash_context = InstallHashContext {
            security_analysis_policy: lpm_store::SecurityAnalysisPolicy::Disabled,
            dependency_engine_key: "none",
        };
        let platform = PlatformTuple::current();
        write_install_hash_with_known_runtime_state_and_mtime_policy(
            root,
            "fakehash",
            lpm_linker::LinkerMode::Isolated,
            ObjectIntegrityPolicy::Source,
            &platform,
            hash_context.dependency_engine_key,
            KnownInstallHashRuntimeState {
                lockfile_path: &lock_path,
                node_runtime_fingerprint: None,
                security_analysis_policy: hash_context.security_analysis_policy,
                sync_noop_proof: None,
                release_age_policy_key: None,
            },
            InstallHashMtimePolicy::Verified {
                pkg_stamp,
                lock_stamp: Some(lock_stamp),
            },
        )
        .unwrap();

        let hash_file = root.join(".lpm/install-hash");
        let saved = fs::read_to_string(&hash_file).unwrap();
        assert!(
            saved.lines().any(|line| line.starts_with("t:")),
            "verified save must write a t: stamp line"
        );
        // Valid t: line hits the fast path directly.
        assert!(
            try_mtime_fast_path_with_cached_content(
                root,
                &lock_path,
                pkg,
                Some(&saved),
                lpm_linker::LinkerMode::Isolated,
                ObjectIntegrityPolicy::Source,
                &platform,
                lpm_store::StoreVersion::V2,
                hash_context,
            )
            .is_some(),
            "unchanged files with valid t: stamp must hit mtime fast path"
        );

        // Legacy install-hash with NO t: line stays compatible.
        let without_t: String = saved
            .lines()
            .filter(|line| !line.starts_with("t:"))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(
            try_mtime_fast_path_with_cached_content(
                root,
                &lock_path,
                pkg,
                Some(&without_t),
                lpm_linker::LinkerMode::Isolated,
                ObjectIntegrityPolicy::Source,
                &platform,
                lpm_store::StoreVersion::V2,
                hash_context,
            )
            .is_some(),
            "legacy install-hash without t: line must remain eligible for mtime fast path"
        );

        // A present-but-malformed t: line must force slow-path verification.
        let malformed_t: String = saved
            .lines()
            .map(|line| {
                if line.starts_with("t:") {
                    "t:corrupted\n".to_string()
                } else {
                    format!("{line}\n")
                }
            })
            .collect();
        assert!(
            try_mtime_fast_path_with_cached_content(
                root,
                &lock_path,
                pkg,
                Some(&malformed_t),
                lpm_linker::LinkerMode::Isolated,
                ObjectIntegrityPolicy::Source,
                &platform,
                lpm_store::StoreVersion::V2,
                hash_context,
            )
            .is_none(),
            "malformed t: line must not silently fall back to mtime-only freshness"
        );
    }
}
