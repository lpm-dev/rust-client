//! Aggregate blocked-set across globally-installed packages.
//!
//! Each globally-installed package is its own synthetic project (per
//! the install pipeline routing). When the global install path calls
//! `install::run_with_options`, the inner project install writes
//! `<install_root>/.lpm/build-state.json` the same way any other
//! project install would — just scoped to the global install root.
//!
//! This module walks every install root named in the global manifest,
//! reads its per-install `build-state.json`, and rolls them up into
//! a single aggregate view the `approve-scripts --global` command
//! can operate on.
//!
//! ## Model
//!
//! - **Source of truth:** per-install `build-state.json` files
//!   (produced by the unmodified project install pipeline). This
//!   module reads them; it never writes them.
//! - **Filter layer:** `GlobalTrustedDependencies` (`~/.lpm/global/
//!   trusted-dependencies.json`). A package blocked at the per-install
//!   layer is filtered OUT of the aggregate view if a matching strict
//!   entry exists in the global trust file. Matches the project-level
//!   model where `lpm.trustedDependencies` in `package.json` filters
//!   the per-project blocked set at approve-scripts read time.
//! - **Dedup:** a single package `name@version` with the SAME
//!   `(integrity, script_hash)` appearing in N install roots is
//!   reported ONCE in the aggregate, with a list of which globally-
//!   installed packages transitively depend on it.
//!
//! The `approve-scripts --global` command consumes
//! [`AggregateBlockedSet`] directly. Install-time warnings use
//! [`warn_if_blocked_after_install`] to emit a banner pointing at
//! `lpm approve-scripts --global`.

use crate::build_state::{BlockedPackage, BuildState, build_state_path, read_build_state};
use lpm_common::{LpmError, LpmRoot};
use lpm_global::{GlobalManifest, GlobalTrustMatch, GlobalTrustedDependencies, read_for};
use lpm_security::triage::StaticTier;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One row in the aggregate view. A package blocked because its
/// lifecycle scripts require user approval, plus which globally-
/// installed packages (top-level) pulled it in transitively.
///
/// `origins` is sorted for deterministic output. The same
/// `(name, version)` with different `(source, integrity, script_hash)` tuples
/// produces distinct rows — e.g., if `esbuild@0.25.1` appears in
/// `eslint`'s tree with binding A and in `typescript`'s tree with
/// binding B (tarball swap between installs), the user needs to
/// review both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateBlockedRow {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub integrity: Option<String>,
    pub script_hash: Option<String>,
    /// Which lifecycle phases are present (preinstall/install/postinstall).
    /// Inherited from the per-install blocked-package entry.
    pub phases_present: Vec<String>,
    /// True iff the per-install layer already saw a rich trust binding
    /// that drifted — matches `BlockedPackage::binding_drift`. Surfaced
    /// through to approve-scripts for "previously approved, now drifted"
    /// messaging.
    pub binding_drift: bool,
    /// Static-tier classification carried from the per-install
    /// [`BlockedPackage::static_tier`]. `None` when the per-install
    /// capture predates static-tier classification, or when the install
    /// was captured with `script-policy = "deny" | "allow"` (no
    /// classification applied).
    ///
    /// When the same `(name, version, source, integrity, script_hash)` aggregate
    /// row is contributed by multiple origins, the strictest tier wins
    /// (see [`merge_static_tier`]) — conservative for the gate that
    /// consumes this field.
    pub static_tier: Option<StaticTier>,
    /// Globally-installed package names (top-level of each install root)
    /// whose transitive tree contains this blocked package. Sorted.
    pub origins: Vec<String>,
}

/// Promote two tier hints to the strictest. Used at dedup-merge time
/// when the same `(name, version, source, integrity, script_hash)` is reported
/// by more than one origin and the two origins disagree on tier.
///
/// Precedence (most-strict first): `Red > AmberLlm > Amber > Green > None`.
/// The gate that consumes the aggregate refuses non-green tiers, so a
/// "promote to strictest" merge keeps the policy boundary at the most
/// conservative reading — a Red contribution from any origin keeps the
/// row blocked from bulk approval even if another origin labelled the
/// same binding Green.
fn merge_static_tier(a: Option<StaticTier>, b: Option<StaticTier>) -> Option<StaticTier> {
    fn rank(t: Option<StaticTier>) -> u8 {
        match t {
            None => 0,
            Some(StaticTier::Green) => 1,
            Some(StaticTier::Amber) => 2,
            Some(StaticTier::AmberLlm) => 3,
            Some(StaticTier::Red) => 4,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

/// Output of [`aggregate_blocked_across_globals`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AggregateBlockedSet {
    /// Deduped blocked packages, sorted by `(name, version, source, integrity,
    /// script_hash)` for deterministic output.
    pub rows: Vec<AggregateBlockedRow>,
    /// Global-manifest entries whose per-install build-state file was
    /// missing or unreadable. Reported so the caller can surface a
    /// soft warning — these installs may predate build-state tracking (no
    /// build-state ever written) or may have a corrupted `.lpm/` dir. Not a fatal
    /// condition for approve-scripts.
    pub unreadable_origins: Vec<String>,
}

/// Read the global manifest, walk every install's `build-state.json`,
/// filter via the global trusted-deps, and roll up into one view.
///
/// Returns an empty aggregate if no global manifest exists, matching
/// the "fresh machine" case. Missing per-install state files are
/// reported in `unreadable_origins` (not an error).
pub fn aggregate_blocked_across_globals(root: &LpmRoot) -> Result<AggregateBlockedSet, LpmError> {
    let manifest = read_global_manifest_or_empty(root)?;
    let trusted = lpm_global::trusted_deps::read_for(root)?;
    Ok(aggregate_with_manifest_and_trust(root, &manifest, &trusted))
}

/// Lower-level helper exposed for testing: the caller supplies the
/// manifest + trust snapshot directly, so the test doesn't have to
/// materialize a real `~/.lpm/global/` tree.
pub fn aggregate_with_manifest_and_trust(
    root: &LpmRoot,
    manifest: &GlobalManifest,
    trusted: &GlobalTrustedDependencies,
) -> AggregateBlockedSet {
    // Keyed by `(name, version, source, integrity-or-empty, script_hash-or-empty)`
    // so DIFFERENT bindings for the same name@version stay separate.
    let mut by_key: BTreeMap<DedupKey, (AggregateBlockedRow, Vec<String>)> = BTreeMap::new();
    let mut unreadable_origins: Vec<String> = Vec::new();

    for (pkg_name, entry) in &manifest.packages {
        if entry.source == lpm_global::PackageSource::LocalLink {
            continue;
        }
        let install_root = root.global_root().join(&entry.root);
        let Some(per_install_state) = read_build_state_for_install(&install_root) else {
            unreadable_origins.push(pkg_name.clone());
            continue;
        };
        for blocked in per_install_state.blocked_packages {
            // Filter: skip if this package is already covered by a
            // strict global trust entry.
            let trust_match = trusted.matches_strict(
                &blocked.name,
                &blocked.version,
                blocked.source.as_deref(),
                blocked.integrity.as_deref(),
                blocked.script_hash.as_deref(),
            );
            if matches!(trust_match, GlobalTrustMatch::Strict) {
                continue;
            }
            // A drift match from the global layer takes precedence
            // over the per-install drift flag: if the global store
            // says "we had a rich entry for this, but the binding
            // changed," surface drift. Otherwise inherit the
            // per-install flag.
            let binding_drift = matches!(trust_match, GlobalTrustMatch::BindingDrift { .. })
                || blocked.binding_drift;

            let key = DedupKey::from_blocked(&blocked);
            let row_tier = blocked.static_tier;
            let (row, _) = by_key.entry(key).or_insert_with(|| {
                (
                    AggregateBlockedRow {
                        name: blocked.name.clone(),
                        version: blocked.version.clone(),
                        source: blocked.source.clone(),
                        integrity: blocked.integrity.clone(),
                        script_hash: blocked.script_hash.clone(),
                        phases_present: blocked.phases_present.clone(),
                        binding_drift,
                        static_tier: row_tier,
                        origins: Vec::new(),
                    },
                    Vec::new(),
                )
            });
            // Append unique origins — the same install root may
            // legitimately appear only once, but defend against
            // duplicate rows in a single state file.
            if !row.origins.contains(pkg_name) {
                row.origins.push(pkg_name.clone());
            }
            // Any drift seen anywhere promotes the row to drift.
            if binding_drift {
                row.binding_drift = true;
            }
            // Any non-green tier seen at ANY origin promotes the row's
            // tier to the strictest — conservative for the gate at
            // approve-scripts --global --yes.
            row.static_tier = merge_static_tier(row.static_tier, row_tier);
        }
    }

    let mut rows: Vec<AggregateBlockedRow> = by_key.into_values().map(|(r, _)| r).collect();
    for row in &mut rows {
        row.origins.sort();
    }
    // BTreeMap gives us deterministic key order; convert that into
    // the sorted rows list directly.
    rows.sort_by(|a, b| {
        (
            a.name.as_str(),
            a.version.as_str(),
            &a.source,
            &a.integrity,
            &a.script_hash,
        )
            .cmp(&(
                b.name.as_str(),
                b.version.as_str(),
                &b.source,
                &b.integrity,
                &b.script_hash,
            ))
    });
    unreadable_origins.sort();

    AggregateBlockedSet {
        rows,
        unreadable_origins,
    }
}

/// Read `<install_root>/.lpm/build-state.json`. Returns `None` for
/// missing OR malformed — same treatment as the project-level reader
/// (schema version mismatch is also `None`). The aggregate caller
/// reports this as an "unreadable origin" rather than a hard error.
fn read_build_state_for_install(install_root: &std::path::Path) -> Option<BuildState> {
    read_build_state(install_root)
}

fn read_global_manifest_or_empty(root: &LpmRoot) -> Result<GlobalManifest, LpmError> {
    if !root.global_manifest().exists() {
        return Ok(GlobalManifest::default());
    }
    read_for(root)
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct DedupKey {
    name: String,
    version: String,
    source: String,
    integrity: String, // "" when None
    script_hash: String,
}

impl DedupKey {
    fn from_blocked(b: &BlockedPackage) -> Self {
        Self {
            name: b.name.clone(),
            version: b.version.clone(),
            source: b.source.clone().unwrap_or_default(),
            integrity: b.integrity.clone().unwrap_or_default(),
            script_hash: b.script_hash.clone().unwrap_or_default(),
        }
    }
}

/// Quiet assertion for consumers that want to know where a specific
/// install's build-state lives — currently only used by tests but
/// exposed for doctor integration where reading the file directly
/// is useful for diagnostics.
#[allow(dead_code)]
pub fn build_state_path_for_install(install_root: &std::path::Path) -> PathBuf {
    build_state_path(install_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_state::{BUILD_STATE_VERSION, compute_blocked_set_fingerprint};
    use chrono::Utc;
    use lpm_global::{PackageEntry, PackageSource};

    fn seed_install_with_blocked(
        root: &LpmRoot,
        pkg_name: &str,
        version: &str,
        blocked: Vec<BlockedPackage>,
    ) -> String {
        let rel_root = format!("installs/{pkg_name}@{version}");
        let install_root = root.global_root().join(&rel_root);
        std::fs::create_dir_all(&install_root).unwrap();
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: compute_blocked_set_fingerprint(&blocked),
            captured_at: Utc::now().to_rfc3339(),
            blocked_packages: blocked,
            drift_ignore_override: None,
        };
        crate::build_state::write_build_state(&install_root, &state).unwrap();
        rel_root
    }

    fn pkg_entry(rel_root: &str, version: &str) -> PackageEntry {
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: version.into(),
            integrity: "sha512-test".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: rel_root.into(),
            commands: vec![],
        }
    }

    fn blocked(
        name: &str,
        version: &str,
        integ: Option<&str>,
        script: Option<&str>,
    ) -> BlockedPackage {
        BlockedPackage {
            name: name.into(),
            version: version.into(),
            source: Some("registry+https://registry.npmjs.org".into()),
            integrity: integ.map(String::from),
            script_hash: script.map(String::from),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            // fields default to None in global-blocked-set
            // test helpers. Global-scope triage is (see
            //); until then these fields remain None through the
            // global flow even when the project-scope flow populates
            // them.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    #[test]
    fn aggregate_returns_empty_when_no_global_manifest_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert!(agg.rows.is_empty());
        assert!(agg.unreadable_origins.is_empty());
    }

    #[test]
    fn aggregate_rolls_up_blocked_from_all_install_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let rel_eslint = seed_install_with_blocked(
            &root,
            "eslint",
            "9.24.0",
            vec![blocked("esbuild", "0.25.1", Some("i-a"), Some("s-a"))],
        );
        let rel_tsc = seed_install_with_blocked(
            &root,
            "typescript",
            "5.8.0",
            vec![blocked("sharp", "0.33.0", Some("i-b"), Some("s-b"))],
        );
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("eslint".into(), pkg_entry(&rel_eslint, "9.24.0"));
        manifest
            .packages
            .insert("typescript".into(), pkg_entry(&rel_tsc, "5.8.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(agg.rows.len(), 2);
        assert_eq!(agg.rows[0].name, "esbuild");
        assert_eq!(agg.rows[0].origins, vec!["eslint"]);
        assert_eq!(agg.rows[1].name, "sharp");
        assert_eq!(agg.rows[1].origins, vec!["typescript"]);
    }

    /// Same package pulled in by two globally-installed packages with
    /// the same (integrity, script_hash) must appear once with both
    /// origins listed.
    #[test]
    fn aggregate_dedups_same_package_across_multiple_origins() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let shared_blocked = blocked("esbuild", "0.25.1", Some("i-same"), Some("s-same"));
        let rel_a = seed_install_with_blocked(&root, "a", "1.0.0", vec![shared_blocked.clone()]);
        let rel_b = seed_install_with_blocked(&root, "b", "1.0.0", vec![shared_blocked]);
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("a".into(), pkg_entry(&rel_a, "1.0.0"));
        manifest
            .packages
            .insert("b".into(), pkg_entry(&rel_b, "1.0.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(agg.rows.len(), 1);
        assert_eq!(agg.rows[0].origins, vec!["a", "b"]);
    }

    /// Different (integrity, script_hash) pairs for the same
    /// name@version must NOT dedup — the user needs to review each
    /// distinct binding independently.
    #[test]
    fn aggregate_does_not_dedup_across_different_bindings() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let rel_a = seed_install_with_blocked(
            &root,
            "a",
            "1.0.0",
            vec![blocked("esbuild", "0.25.1", Some("i-A"), Some("s-A"))],
        );
        let rel_b = seed_install_with_blocked(
            &root,
            "b",
            "1.0.0",
            vec![blocked("esbuild", "0.25.1", Some("i-B"), Some("s-B"))],
        );
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("a".into(), pkg_entry(&rel_a, "1.0.0"));
        manifest
            .packages
            .insert("b".into(), pkg_entry(&rel_b, "1.0.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(
            agg.rows.len(),
            2,
            "different bindings must be separate rows"
        );
    }

    #[test]
    fn aggregate_filters_out_globally_trusted_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let rel = seed_install_with_blocked(
            &root,
            "eslint",
            "9.24.0",
            vec![blocked("esbuild", "0.25.1", Some("i-T"), Some("s-T"))],
        );
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("eslint".into(), pkg_entry(&rel, "9.24.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        // Approve `esbuild@0.25.1` globally with a matching binding.
        let mut trust = GlobalTrustedDependencies::default();
        trust.insert_binding_for_identity(
            "esbuild",
            "0.25.1",
            Some("registry+https://registry.npmjs.org".into()),
            lpm_global::TrustedDependencyBinding {
                source: None,
                integrity: Some("i-T".into()),
                script_hash: Some("s-T".into()),
                provenance_at_approval: None,
            },
        );
        lpm_global::trusted_deps::write_for(&root, &trust).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert!(
            agg.rows.is_empty(),
            "trusted package must be filtered out of the aggregate"
        );
    }

    /// Global trust with a MISMATCHED binding surfaces as drift (not
    /// filtered). Matches the project-level behaviour.
    #[test]
    fn aggregate_promotes_to_drift_when_global_trust_binding_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let rel = seed_install_with_blocked(
            &root,
            "eslint",
            "9.24.0",
            vec![blocked("esbuild", "0.25.1", Some("i-NEW"), Some("s-NEW"))],
        );
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("eslint".into(), pkg_entry(&rel, "9.24.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        // Trust has the OLD binding.
        let mut trust = GlobalTrustedDependencies::default();
        trust.insert_strict(
            "esbuild",
            "0.25.1",
            Some("i-OLD".into()),
            Some("s-OLD".into()),
        );
        lpm_global::trusted_deps::write_for(&root, &trust).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(agg.rows.len(), 1);
        assert!(
            agg.rows[0].binding_drift,
            "global-trust mismatch must surface as drift"
        );
    }

    #[test]
    fn aggregate_reports_unreadable_origins() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        // Manifest claims an install root, but no build-state.json exists.
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("orphan".into(), pkg_entry("installs/orphan@1.0.0", "1.0.0"));
        // Create the install dir so it's not an absent-install case,
        // just a missing state file.
        std::fs::create_dir_all(root.global_root().join("installs/orphan@1.0.0")).unwrap();
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert!(agg.rows.is_empty());
        assert_eq!(agg.unreadable_origins, vec!["orphan".to_string()]);
    }

    fn blocked_tiered(
        name: &str,
        version: &str,
        integ: Option<&str>,
        script: Option<&str>,
        tier: StaticTier,
    ) -> BlockedPackage {
        let mut b = blocked(name, version, integ, script);
        b.static_tier = Some(tier);
        b
    }

    /// End-to-end JSON → aggregate: writes the same `build-state.json`
    /// shape the workflow fixtures produce, then asserts the tier
    /// survives `read_build_state` → aggregator. Protects against a
    /// future serde rename that breaks the wire shape — the in-memory
    /// `aggregate_carries_static_tier_from_per_install_state` test
    /// alone wouldn't catch a JSON-field-name regression.
    #[test]
    fn aggregate_reads_static_tier_from_disk_json() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/eslint@9.24.0");
        let lpm_dir = install_root.join(".lpm");
        std::fs::create_dir_all(&lpm_dir).unwrap();
        std::fs::write(
            lpm_dir.join("build-state.json"),
            br#"{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-fixture",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": [
        {
            "name": "esbuild",
            "version": "0.25.1",
            "integrity": "sha512-fixture",
            "script_hash": "sha256-fixture",
            "phases_present": ["postinstall"],
            "binding_drift": false,
            "static_tier": "amber"
        }
    ]
}"#,
        )
        .unwrap();
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "eslint".into(),
            pkg_entry("installs/eslint@9.24.0", "9.24.0"),
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(agg.rows.len(), 1, "expected one aggregate row");
        assert_eq!(
            agg.rows[0].static_tier,
            Some(StaticTier::Amber),
            "JSON `\"static_tier\": \"amber\"` must deserialize and \
             propagate to the aggregate row"
        );
    }

    /// The aggregate row must carry the per-install `static_tier` so the
    /// `--yes` gate at approve-scripts --global can refuse non-green
    /// bulk approvals. Pin the propagation contract — pre-fix the
    /// aggregate dropped the tier silently and the gate had no signal.
    #[test]
    fn aggregate_carries_static_tier_from_per_install_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let rel = seed_install_with_blocked(
            &root,
            "eslint",
            "9.24.0",
            vec![blocked_tiered(
                "esbuild",
                "0.25.1",
                Some("i-a"),
                Some("s-a"),
                StaticTier::Amber,
            )],
        );
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("eslint".into(), pkg_entry(&rel, "9.24.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(agg.rows.len(), 1);
        assert_eq!(agg.rows[0].static_tier, Some(StaticTier::Amber));
    }

    /// Same `(name, version, source, integrity, script_hash)` reported by two
    /// installs with disagreeing tiers must collapse to the strictest:
    /// `Red > AmberLlm > Amber > Green > None`. The gate that consumes
    /// this field treats non-green as refusal, so promoting to strictest
    /// at merge is the conservative-by-design choice.
    #[test]
    fn aggregate_promotes_to_strictest_tier_when_origins_disagree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Both installs report the SAME (integrity, script_hash) so the
        // dedup collapses them; the tier differs to exercise the merge.
        let row_green = blocked_tiered(
            "esbuild",
            "0.25.1",
            Some("i-same"),
            Some("s-same"),
            StaticTier::Green,
        );
        let row_red = blocked_tiered(
            "esbuild",
            "0.25.1",
            Some("i-same"),
            Some("s-same"),
            StaticTier::Red,
        );
        let rel_a = seed_install_with_blocked(&root, "a", "1.0.0", vec![row_green]);
        let rel_b = seed_install_with_blocked(&root, "b", "1.0.0", vec![row_red]);
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("a".into(), pkg_entry(&rel_a, "1.0.0"));
        manifest
            .packages
            .insert("b".into(), pkg_entry(&rel_b, "1.0.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let agg = aggregate_blocked_across_globals(&root).unwrap();
        assert_eq!(agg.rows.len(), 1, "dedup should collapse to one row");
        assert_eq!(
            agg.rows[0].static_tier,
            Some(StaticTier::Red),
            "Red must dominate Green at merge"
        );
        assert_eq!(agg.rows[0].origins, vec!["a", "b"]);
    }

    /// Direct cover of the rank function so future edits that flip an
    /// ordering pair (e.g. swap AmberLlm above Red) trip a test rather
    /// than silently weaken the gate. Six representative pairings cover
    /// every adjacency in the strictness ladder.
    #[test]
    fn merge_static_tier_precedence_red_over_amber_llm_over_amber_over_green_over_none() {
        let none = None::<StaticTier>;
        let g = Some(StaticTier::Green);
        let a = Some(StaticTier::Amber);
        let al = Some(StaticTier::AmberLlm);
        let r = Some(StaticTier::Red);

        assert_eq!(merge_static_tier(none, g), g);
        assert_eq!(merge_static_tier(g, a), a);
        assert_eq!(merge_static_tier(a, al), al);
        assert_eq!(merge_static_tier(al, r), r);
        // Commutative + idempotent for the equal-tier case.
        assert_eq!(merge_static_tier(r, r), r);
        assert_eq!(merge_static_tier(r, g), r);
    }
}
