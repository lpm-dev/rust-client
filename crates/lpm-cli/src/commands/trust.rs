//! Phase 46 P1 — `lpm trust` user-facing subcommands.
//!
//! Two subcommands, both operating on
//! `<project_dir>/package.json > lpm > trustedDependencies` plus (for
//! `diff`) `<project_dir>/.lpm/trust-snapshot.json` written by the
//! install pipeline.
//!
//! ## `lpm trust diff`
//!
//! Read-only inspection of how the current manifest's trust bindings
//! differ from the last install's snapshot. The install pipeline
//! emits a brief notice for additions (plan §4.2); this command
//! gives the full picture — additions, removals, and same-key
//! binding changes — so the user can investigate before running
//! another install.
//!
//! ## `lpm trust prune`
//!
//! Remove stale `trustedDependencies` entries — ones whose package
//! name no longer appears in the resolved tree (lockfile). Useful
//! after removing a dependency: the approval entry lingers in
//! `package.json` forever otherwise (pre-Phase-46, `lpm build`
//! emits a "stale trustedDependencies" warning; `prune` is the
//! active fix).
//!
//! Per-version trust entries (e.g. `esbuild@0.25.1` when only
//! `esbuild@0.25.2` is installed) are NOT considered stale by name
//! alone — the name is still in the tree, just at a different
//! version. That's drift territory, handled by the strict-gate
//! `BindingDrift` path at install time.

use crate::output;
use crate::trust_snapshot::{self, SnapshotEntry, TrustSnapshot};
use clap::Subcommand;
use lpm_common::LpmError;
use lpm_workspace::{TrustedDependencies, TrustedDependencyBinding};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::path::Path;

/// Stable JSON schema version for `lpm trust {diff,prune} --json`.
///
/// Bumped independently of `build-state.json` / `trust-snapshot.json`
/// schemas because this is a user-facing output contract consumed by
/// agents and scripts. Same "only on breaking changes" discipline
/// as elsewhere in Phase 46.
pub const SCHEMA_VERSION: u32 = 1;

/// `lpm trust <subcommand>`.
#[derive(Debug, Subcommand)]
pub enum TrustCmd {
    /// Show how `package.json > lpm > trustedDependencies` differs
    /// from the last install's snapshot.
    ///
    /// Surfaces additions (potential silent PR poisoning),
    /// removals, and same-key binding changes. Read-only.
    Diff {
        /// Emit machine-readable JSON instead of human output.
        #[arg(long)]
        json: bool,
    },
    /// Remove stale `trustedDependencies` entries (packages no
    /// longer in the resolved tree).
    Prune {
        /// Skip the interactive confirmation prompt. Required on
        /// non-TTY (e.g. CI).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Preview what would be pruned without writing to
        /// `package.json`.
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON instead of human output.
        #[arg(long)]
        json: bool,
    },
}

/// Entry point called from main.rs.
pub async fn run(cmd: &TrustCmd, project_dir: &Path) -> Result<(), LpmError> {
    match cmd {
        TrustCmd::Diff { json } => run_diff(project_dir, *json).await,
        TrustCmd::Prune { yes, dry_run, json } => {
            run_prune(project_dir, *yes, *dry_run, *json).await
        }
    }
}

// ─── lpm trust diff ────────────────────────────────────────────────

/// Classification of a single binding's change between snapshot and
/// current manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DiffKind {
    /// Entry present in current, absent in snapshot.
    Added,
    /// Entry present in snapshot, absent in current.
    Removed,
    /// Same key in both but at least one of (integrity, script_hash)
    /// changed.
    Changed,
}

#[derive(Debug, Clone)]
struct DiffEntry {
    key: String,
    kind: DiffKind,
    previous: Option<SnapshotEntry>,
    current: Option<SnapshotEntry>,
}

/// Compute the full three-way diff between snapshot and current
/// manifest bindings.
///
/// Stable-ordered: additions first (lexicographic), then removals,
/// then changes — matching the rendering convention so downstream
/// JSON consumers don't have to re-sort.
fn compute_full_diff(snapshot: Option<&TrustSnapshot>, current: &TrustSnapshot) -> Vec<DiffEntry> {
    let empty = BTreeMap::new();
    let prev = snapshot.map(|s| &s.bindings).unwrap_or(&empty);
    let curr = &current.bindings;

    let mut added: Vec<DiffEntry> = Vec::new();
    let mut removed: Vec<DiffEntry> = Vec::new();
    let mut changed: Vec<DiffEntry> = Vec::new();

    for (key, curr_entry) in curr {
        match prev.get(key) {
            None => added.push(DiffEntry {
                key: key.clone(),
                kind: DiffKind::Added,
                previous: None,
                current: Some(curr_entry.clone()),
            }),
            Some(prev_entry) if prev_entry != curr_entry => changed.push(DiffEntry {
                key: key.clone(),
                kind: DiffKind::Changed,
                previous: Some(prev_entry.clone()),
                current: Some(curr_entry.clone()),
            }),
            Some(_) => {} // identical, skip
        }
    }
    for (key, prev_entry) in prev {
        if !curr.contains_key(key) {
            removed.push(DiffEntry {
                key: key.clone(),
                kind: DiffKind::Removed,
                previous: Some(prev_entry.clone()),
                current: None,
            });
        }
    }

    // BTreeMap iteration already yields sorted keys; concatenating
    // added → removed → changed preserves lexicographic order WITHIN
    // each class, which is the user-visible rendering order.
    added.extend(removed);
    added.extend(changed);
    added
}

async fn run_diff(project_dir: &Path, json: bool) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "lpm trust diff requires a package.json in the current directory.".into(),
        ));
    }
    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

    let snapshot = trust_snapshot::read_snapshot(project_dir);
    let current = TrustSnapshot::capture_current(
        pkg.lpm
            .as_ref()
            .map(|l| &l.trusted_dependencies)
            .unwrap_or(&TrustedDependencies::Legacy(Vec::new())),
    );
    let entries = compute_full_diff(snapshot.as_ref(), &current);

    if json {
        print_diff_json(&entries, snapshot.as_ref(), &current);
    } else {
        print_diff_human(&entries, snapshot.as_ref());
    }
    Ok(())
}

fn print_diff_json(
    entries: &[DiffEntry],
    snapshot: Option<&TrustSnapshot>,
    current: &TrustSnapshot,
) {
    let body = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "command": "trust diff",
        "snapshot_captured_at": snapshot.map(|s| s.captured_at.clone()),
        "current_binding_count": current.bindings.len(),
        "added": entries.iter().filter(|e| e.kind == DiffKind::Added)
            .map(diff_entry_json).collect::<Vec<_>>(),
        "removed": entries.iter().filter(|e| e.kind == DiffKind::Removed)
            .map(diff_entry_json).collect::<Vec<_>>(),
        "changed": entries.iter().filter(|e| e.kind == DiffKind::Changed)
            .map(diff_entry_json).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

fn diff_entry_json(e: &DiffEntry) -> serde_json::Value {
    serde_json::json!({
        "key": e.key,
        "previous": e.previous,
        "current": e.current,
    })
}

fn print_diff_human(entries: &[DiffEntry], snapshot: Option<&TrustSnapshot>) {
    if entries.is_empty() {
        match snapshot {
            Some(s) => output::success(&format!(
                "trustedDependencies unchanged since last install ({})",
                s.captured_at,
            )),
            None => output::info(
                "no prior snapshot (this project hasn't been installed with LPM before)",
            ),
        }
        return;
    }

    if let Some(s) = snapshot {
        output::info(&format!(
            "trustedDependencies diff vs. snapshot from {}:",
            s.captured_at
        ));
    } else {
        output::info("trustedDependencies (no prior snapshot to compare against):");
    }

    for e in entries {
        match e.kind {
            DiffKind::Added => {
                println!("  {} {}", "+".green(), e.key.bold());
            }
            DiffKind::Removed => {
                println!("  {} {}", "-".red(), e.key.bold());
            }
            DiffKind::Changed => {
                println!("  {} {}", "~".yellow(), e.key.bold());
                if let (Some(prev), Some(curr)) = (&e.previous, &e.current) {
                    render_binding_delta("integrity", &prev.integrity, &curr.integrity);
                    render_binding_delta("scriptHash", &prev.script_hash, &curr.script_hash);
                }
            }
        }
    }
}

fn render_binding_delta(name: &str, prev: &Option<String>, curr: &Option<String>) {
    if prev == curr {
        return;
    }
    let prev_s = prev.as_deref().unwrap_or("<none>");
    let curr_s = curr.as_deref().unwrap_or("<none>");
    println!("      {name}: {} → {}", prev_s.dimmed(), curr_s);
}

// ─── lpm trust prune ───────────────────────────────────────────────

/// Determine which `trustedDependencies` keys are stale — their
/// package NAME no longer appears anywhere in the resolved tree.
///
/// "Name no longer in the resolved tree" means: the lockfile has
/// zero entries with this name, regardless of version. Per-version
/// drift (same name, different version) is NOT stale here — that's
/// BindingDrift at install time.
fn compute_stale_keys(
    trusted: &TrustedDependencies,
    installed_names: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut stale: Vec<String> = Vec::new();
    match trusted {
        TrustedDependencies::Legacy(names) => {
            for n in names {
                if !installed_names.contains(n) {
                    stale.push(n.clone());
                }
            }
        }
        TrustedDependencies::Rich(map) => {
            for key in map.keys() {
                // Rich keys are "name@version"; extract the name half
                // (everything before the LAST `@`, so scoped packages
                // like `@scope/pkg@1.2.3` work).
                let name = match key.rfind('@') {
                    Some(at) if at > 0 => &key[..at],
                    _ => key.as_str(),
                };
                if !installed_names.contains(name) {
                    stale.push(key.clone());
                }
            }
        }
    }
    stale.sort();
    stale
}

/// Read the resolved-tree names from `lpm.lock`. Returns an empty
/// set on missing / malformed lockfile (which prune then interprets
/// as "no names installed → everything looks stale"; we refuse to
/// prune in that case at the caller level).
fn installed_names_from_lockfile(
    project_dir: &Path,
) -> Result<std::collections::HashSet<String>, LpmError> {
    let lockfile_path = project_dir.join("lpm.lock");
    if !lockfile_path.exists() {
        return Err(LpmError::NotFound(
            "no lpm.lock found — run `lpm install` before pruning trust entries".into(),
        ));
    }
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to read lockfile: {e}")))?;
    Ok(lockfile.packages.into_iter().map(|p| p.name).collect())
}

async fn run_prune(
    project_dir: &Path,
    yes: bool,
    dry_run: bool,
    json: bool,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "lpm trust prune requires a package.json in the current directory.".into(),
        ));
    }

    let installed_names = installed_names_from_lockfile(project_dir)?;

    // Load the raw JSON so we can write it back with minimal churn
    // (preserve ordering, whitespace, etc.). Parse
    // `trustedDependencies` via the typed path to reuse the variant-
    // aware stale computation.
    let manifest_text = std::fs::read_to_string(&pkg_json_path).map_err(LpmError::Io)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_text)
        .map_err(|e| LpmError::Registry(format!("failed to parse package.json: {e}")))?;
    let trusted = extract_trusted_dependencies(&manifest);
    let stale = compute_stale_keys(&trusted, &installed_names);

    if json {
        print_prune_json(&stale, dry_run, !stale.is_empty() && !dry_run);
    } else {
        print_prune_human_preview(&stale, &trusted);
    }

    if stale.is_empty() || dry_run {
        return Ok(());
    }

    // Non-TTY without --yes is a hard error: prune mutates
    // package.json. No prompting without explicit opt-in from CI /
    // scripts.
    if !yes && !is_tty() {
        return Err(LpmError::Script(
            "lpm trust prune needs a TTY for confirmation. Pass `--yes` to \
             proceed non-interactively, or `--dry-run` to preview."
                .into(),
        ));
    }
    if !yes && !json {
        let confirmed = cliclack::confirm(format!(
            "Remove {} stale entry/entries from package.json?",
            stale.len()
        ))
        .interact()
        .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
        if !confirmed {
            output::info("Nothing pruned.");
            return Ok(());
        }
    }

    remove_stale_from_manifest(&mut manifest, &stale);
    write_manifest(&pkg_json_path, &manifest)?;

    if !json {
        output::success(&format!(
            "Removed {} stale trust entry/entries.",
            stale.len()
        ));
    }
    Ok(())
}

fn extract_trusted_dependencies(manifest: &serde_json::Value) -> TrustedDependencies {
    manifest
        .get("lpm")
        .and_then(|l| l.get("trustedDependencies"))
        .map(|v| serde_json::from_value::<TrustedDependencies>(v.clone()).unwrap_or_default())
        .unwrap_or_default()
}

fn remove_stale_from_manifest(manifest: &mut serde_json::Value, stale: &[String]) {
    let stale_set: std::collections::HashSet<&str> = stale.iter().map(|s| s.as_str()).collect();

    let Some(td_val) = manifest
        .get_mut("lpm")
        .and_then(|l| l.get_mut("trustedDependencies"))
    else {
        return;
    };

    if let Some(arr) = td_val.as_array_mut() {
        // Legacy form: filter the array in place.
        arr.retain(|v| v.as_str().map(|s| !stale_set.contains(s)).unwrap_or(true));
    } else if let Some(map) = td_val.as_object_mut() {
        // Rich form: filter the map in place.
        map.retain(|k, _| !stale_set.contains(k.as_str()));
    }
}

fn write_manifest(path: &Path, manifest: &serde_json::Value) -> Result<(), LpmError> {
    // Atomic write via temp-then-rename, same pattern as the snapshot
    // writer. Pretty-print with 2-space indent to match the npm/pnpm
    // convention most projects use.
    let body = serde_json::to_string_pretty(manifest)
        .map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{body}\n")).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, path).map_err(LpmError::Io)?;
    Ok(())
}

fn print_prune_human_preview(stale: &[String], _trusted: &TrustedDependencies) {
    if stale.is_empty() {
        output::success("No stale trust entries. package.json unchanged.");
        return;
    }
    output::info(&format!(
        "{} stale trust entry/entries (no longer in the resolved tree):",
        stale.len()
    ));
    for k in stale {
        println!("  {} {}", "-".red(), k.bold());
    }
}

fn print_prune_json(stale: &[String], dry_run: bool, will_mutate: bool) {
    let body = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "command": "trust prune",
        "dry_run": dry_run,
        "mutated": will_mutate,
        "stale_count": stale.len(),
        "stale": stale,
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

// Unused import guard for the `Binding` type (referenced via
// `compute_full_diff`'s struct fields). Silences a dead-code warning
// if snapshot/current paths ever get refactored; keeps the type
// linked into this module intentionally.
#[allow(dead_code)]
fn _binding_anchor(_b: &TrustedDependencyBinding) {}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_workspace::TrustedDependencyBinding;
    use std::collections::{HashMap, HashSet};
    use tempfile::tempdir;

    fn rich_td(entries: &[(&str, Option<&str>, Option<&str>)]) -> TrustedDependencies {
        let mut map: HashMap<String, TrustedDependencyBinding> = HashMap::new();
        for (k, integ, sh) in entries {
            map.insert(
                (*k).to_string(),
                TrustedDependencyBinding {
                    integrity: integ.map(String::from),
                    script_hash: sh.map(String::from),
                    ..Default::default()
                },
            );
        }
        TrustedDependencies::Rich(map)
    }

    fn name_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    // ── compute_full_diff ──────────────────────────────────────────

    #[test]
    fn diff_empty_current_and_snapshot_yields_nothing() {
        let curr = TrustSnapshot::capture_current(&TrustedDependencies::default());
        let entries = compute_full_diff(None, &curr);
        assert!(entries.is_empty());
    }

    #[test]
    fn diff_classifies_added_removed_changed() {
        // Snapshot: {esbuild@1, sharp@1}
        // Current:  {esbuild@1 (different hash), axios@1}
        // Expected: added axios@1, removed sharp@1, changed esbuild@1
        let snap = TrustSnapshot::capture_current(&rich_td(&[
            ("esbuild@1.0.0", Some("sha512-old"), Some("sha256-old")),
            ("sharp@1.0.0", None, None),
        ]));
        let curr = TrustSnapshot::capture_current(&rich_td(&[
            ("esbuild@1.0.0", Some("sha512-new"), Some("sha256-new")),
            ("axios@1.0.0", None, None),
        ]));
        let entries = compute_full_diff(Some(&snap), &curr);
        // Expect exactly 3 entries: 1 added + 1 removed + 1 changed.
        assert_eq!(entries.len(), 3);
        let kinds: Vec<&DiffKind> = entries.iter().map(|e| &e.kind).collect();
        // Ordering is added → removed → changed per impl contract.
        assert_eq!(
            kinds,
            vec![&DiffKind::Added, &DiffKind::Removed, &DiffKind::Changed],
            "diff ordering must be added-then-removed-then-changed"
        );
        assert_eq!(entries[0].key, "axios@1.0.0");
        assert_eq!(entries[1].key, "sharp@1.0.0");
        assert_eq!(entries[2].key, "esbuild@1.0.0");
    }

    #[test]
    fn diff_identical_yields_nothing() {
        let td = rich_td(&[("esbuild@1.0.0", Some("sha512-x"), Some("sha256-y"))]);
        let snap = TrustSnapshot::capture_current(&td);
        let curr = TrustSnapshot::capture_current(&td);
        let entries = compute_full_diff(Some(&snap), &curr);
        assert!(
            entries.is_empty(),
            "identical snapshot+current must produce NO diff entries"
        );
    }

    // ── compute_stale_keys ─────────────────────────────────────────

    #[test]
    fn prune_rich_entries_by_name_strips_version_for_lookup() {
        // esbuild@0.25.1 trusted; lockfile has esbuild@0.25.2 → name
        // still installed, NOT stale. sharp@1.0.0 trusted; lockfile
        // has no sharp → stale.
        let td = rich_td(&[("esbuild@0.25.1", None, None), ("sharp@1.0.0", None, None)]);
        let installed = name_set(&["esbuild", "lodash"]);
        let stale = compute_stale_keys(&td, &installed);
        assert_eq!(stale, vec!["sharp@1.0.0".to_string()]);
    }

    #[test]
    fn prune_rich_scoped_package_name_extraction() {
        // `@scope/pkg@1.2.3` must strip to `@scope/pkg` (last `@`,
        // not the first one).
        let td = rich_td(&[("@myorg/secret@1.0.0", None, None)]);
        let installed_with = name_set(&["@myorg/secret"]);
        let installed_without: HashSet<String> = HashSet::new();
        assert!(
            compute_stale_keys(&td, &installed_with).is_empty(),
            "scoped name in lockfile → not stale"
        );
        assert_eq!(
            compute_stale_keys(&td, &installed_without),
            vec!["@myorg/secret@1.0.0".to_string()],
        );
    }

    #[test]
    fn prune_legacy_entries_by_bare_name() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".into(), "gone".into()]);
        let installed = name_set(&["esbuild"]);
        let stale = compute_stale_keys(&td, &installed);
        assert_eq!(stale, vec!["gone".to_string()]);
    }

    #[test]
    fn prune_empty_trusted_yields_no_stale() {
        let td = TrustedDependencies::default();
        let installed = name_set(&[]);
        let stale = compute_stale_keys(&td, &installed);
        assert!(stale.is_empty());
    }

    #[test]
    fn prune_ignores_version_drift_not_stale() {
        // Regression: PER-version entries (esbuild@1 trusted but the
        // tree has esbuild@2) are NOT pruned by this command. The
        // name IS installed; version drift is a BindingDrift concern.
        let td = rich_td(&[("esbuild@1.0.0", None, None)]);
        let installed = name_set(&["esbuild"]);
        assert!(
            compute_stale_keys(&td, &installed).is_empty(),
            "version drift must NOT be flagged as stale by `trust prune`"
        );
    }

    // ── remove_stale_from_manifest ─────────────────────────────────

    #[test]
    fn remove_stale_rich_map_in_place() {
        let mut manifest: serde_json::Value = serde_json::from_str(
            r#"{
                "name": "proj",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@1.0.0": {"integrity": "sha512-e"},
                        "sharp@1.0.0": {"integrity": "sha512-s"}
                    }
                }
            }"#,
        )
        .unwrap();
        remove_stale_from_manifest(&mut manifest, &["sharp@1.0.0".to_string()]);
        let td = manifest
            .get("lpm")
            .unwrap()
            .get("trustedDependencies")
            .unwrap();
        assert!(td.get("esbuild@1.0.0").is_some());
        assert!(td.get("sharp@1.0.0").is_none());
    }

    #[test]
    fn remove_stale_legacy_array_in_place() {
        let mut manifest: serde_json::Value = serde_json::from_str(
            r#"{"name":"proj","lpm":{"trustedDependencies":["esbuild","sharp"]}}"#,
        )
        .unwrap();
        remove_stale_from_manifest(&mut manifest, &["sharp".to_string()]);
        let arr = manifest
            .get("lpm")
            .unwrap()
            .get("trustedDependencies")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], serde_json::Value::String("esbuild".into()));
    }

    #[test]
    fn remove_stale_nonexistent_key_is_noop() {
        let mut manifest: serde_json::Value = serde_json::from_str(
            r#"{"name":"proj","lpm":{"trustedDependencies":{"esbuild@1.0.0":{}}}}"#,
        )
        .unwrap();
        let original = manifest.clone();
        remove_stale_from_manifest(&mut manifest, &["nonexistent".to_string()]);
        assert_eq!(manifest, original);
    }

    // ── write_manifest atomicity ───────────────────────────────────

    #[test]
    fn write_manifest_atomic_no_tmp_leaks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package.json");
        let manifest: serde_json::Value = serde_json::from_str(r#"{"name":"proj"}"#).unwrap();
        write_manifest(&path, &manifest).unwrap();

        assert!(path.exists());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "atomic write must not leak tmp file"
        );
        // Preserves pretty-print + trailing newline.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("{\n"));
        assert!(content.ends_with("}\n"));
    }

    // ── end-to-end prune on a real manifest ────────────────────────

    #[test]
    fn prune_removes_stale_entry_and_leaves_active_entry_intact() {
        let dir = tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{
                "name": "proj",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@1.0.0": {"integrity": "sha512-e"},
                        "sharp@1.0.0": {"integrity": "sha512-s"}
                    }
                }
            }"#,
        )
        .unwrap();

        // Fake lockfile with only esbuild installed.
        let lockfile = lpm_lockfile::Lockfile {
            metadata: lpm_lockfile::LockfileMetadata {
                lockfile_version: 1,
                resolved_with: Some("test".into()),
            },
            packages: vec![lpm_lockfile::LockedPackage {
                name: "esbuild".into(),
                version: "1.0.0".into(),
                ..Default::default()
            }],
            root_aliases: Default::default(),
        };
        let lock_toml = lockfile.to_toml().unwrap();
        std::fs::write(dir.path().join("lpm.lock"), lock_toml).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(run_prune(
            dir.path(),
            true, /* yes */
            false,
            true, /* json */
        ))
        .unwrap();

        let after = std::fs::read_to_string(&pkg_json).unwrap();
        let after_json: serde_json::Value = serde_json::from_str(&after).unwrap();
        let td = after_json
            .get("lpm")
            .unwrap()
            .get("trustedDependencies")
            .unwrap();
        assert!(
            td.get("esbuild@1.0.0").is_some(),
            "active entry must survive prune"
        );
        assert!(
            td.get("sharp@1.0.0").is_none(),
            "stale entry must be removed"
        );
    }
}
