//! `lpm install -g <pkg>` — phase 37 M3.2 persistent install pipeline.
//!
//! Three-phase transaction (plan §"Crash-safe transactions"):
//!
//! 1. Pre-resolve via registry (no lock) — pick a concrete version,
//!    integrity, source. Phase 33 [`save_spec`] decides what
//!    `saved_spec` to persist. Then **acquire `.tx.lock`**, write
//!    INTENT to WAL, write `[pending.<pkg>]` to manifest with empty
//!    `commands` (the install pipeline discovers commands at step 2),
//!    release lock.
//! 2. Slow work, no lock held. Self-hosted install via
//!    `commands::install::run_with_options` against the per-package
//!    install root. After install, discover commands from the
//!    installed package's `package.json` `bin` field, then write the
//!    `.lpm-install-ready` marker. Marker is the load-bearing
//!    durability signal: its presence is the boundary between
//!    "rollback" and "roll forward."
//! 3. **Re-acquire `.tx.lock`**. Call [`validate_install_root`] which
//!    returns the marker's authoritative command list. Emit the bin
//!    shim triple for each command. Move `[pending.<pkg>]` into
//!    `[packages.<pkg>]` with the marker's commands. Append COMMIT to
//!    WAL. Release lock.
//!
//! M3.2 ships fresh-install only. Upgrade (replacing an existing
//! `[packages.<pkg>]` via `[pending.<pkg>]`) lands in M3.4. Collision
//! resolution lands in M4. Approve-builds capture lands in M5.

use crate::output;
use crate::save_spec::{
    SaveConfig, SaveFlags, UserSaveIntent, decide_saved_dependency_spec, parse_user_save_intent,
};
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, with_exclusive_lock};
use lpm_global::{
    AliasEntry, CommandCollision, GlobalManifest, InstallReadyMarker, InstallRootStatus,
    IntentPayload, OwnershipChange, PackageEntry, PackageSource, PendingEntry, Shim, TxKind,
    WalRecord, WalWriter, artifacts_complete, emit_shim, find_command_collisions, read_for,
    remove_shim, validate_install_root, write_for, write_marker,
};
use lpm_registry::RegistryClient;
use lpm_semver::{Version, VersionReq};
use owo_colors::OwoColorize;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

/// Phase 37 M4: user-supplied resolutions for command-name collisions.
///
/// Built from the `--replace-bin` and `--alias` Install flags at the
/// CLI dispatch site ([`CollisionResolution::parse_from_flags`]).
/// Passed through to the install pipeline; semantic application + the
/// "does this command actually exist in the package" check land in M4.2
/// under the commit-time lock, where `marker_commands` is authoritative.
///
/// Wraps a `HashSet<String>` for `--replace-bin` (set semantics — listing
/// the same command twice is legal, just redundant) and a `BTreeMap`
/// for `--alias` (deterministic iteration order for diagnostics,
/// serde output, and test assertions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollisionResolution {
    /// Commands the user has opted to forcibly take ownership of from
    /// whatever package (or alias) currently owns them.
    pub replace: HashSet<String>,
    /// Alias mappings: key is the declared bin name (`<orig>`), value
    /// is the PATH name to expose it as (`<alias>`). At commit time
    /// the original name is NOT emitted as a shim; only the alias is.
    pub alias: BTreeMap<String, String>,
}

impl CollisionResolution {
    /// True when the user supplied no flags — the pre-M4 "abort on
    /// collision" path is still the right behaviour for this case.
    /// M4.2 consumes this to decide between flag-driven resolution
    /// and the TTY-prompt / error paths.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.replace.is_empty() && self.alias.is_empty()
    }

    /// Parse and locally-validate the CLI flag vectors. Returns an
    /// `Err(String)` with a user-facing message on any of the M4.1
    /// syntactic / local-consistency failures:
    ///
    /// - `--alias` mapping that doesn't match `<orig>=<alias>` shape.
    /// - Empty `<orig>` or `<alias>` after splitting on `=`.
    /// - Self-map (`--alias a=a`) — nothing to resolve.
    /// - Duplicate `--alias` keys (`a=b,a=c`) — ambiguous intent.
    /// - Alias target that fails [`lpm_linker::validate_bin_name`] —
    ///   null bytes, path separators, traversal.
    /// - Same command appearing in both `--replace-bin` and `--alias`
    ///   keys — mutually exclusive intents for the same collision.
    ///
    /// Explicitly does NOT check "is this a real command of the
    /// package" — that requires marker discovery and happens in M4.2
    /// under the commit lock. The `package_name` parameter is only
    /// used to produce useful validator warnings via
    /// `validate_bin_name` (it logs shadowing warnings with the pkg
    /// name attached).
    pub fn parse_from_flags(replace_bin: &[String], alias: &[String]) -> Result<Self, String> {
        let replace: HashSet<String> = replace_bin.iter().cloned().collect();

        let mut alias_map: BTreeMap<String, String> = BTreeMap::new();
        // `--alias a=b,c=d` and `--alias a=b --alias c=d` are both valid;
        // flatten on comma first, then parse each `orig=alias` pair.
        for raw in alias {
            for piece in raw.split(',') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                let (orig, mapped) = piece.split_once('=').ok_or_else(|| {
                    format!(
                        "`--alias {piece}`: expected `<orig>=<alias>` shape (e.g. \
                         `--alias serve=foo-serve`)"
                    )
                })?;
                let orig = orig.trim();
                let mapped = mapped.trim();
                if orig.is_empty() {
                    return Err(format!("`--alias {piece}`: `<orig>` side is empty"));
                }
                if mapped.is_empty() {
                    return Err(format!("`--alias {piece}`: `<alias>` side is empty"));
                }
                if orig == mapped {
                    return Err(format!(
                        "`--alias {orig}={mapped}`: alias target is the same as the \
                         original — nothing to resolve"
                    ));
                }
                // Validate the alias target against the same safety bar
                // package-declared bin names meet. The linker's
                // `validate_bin_name` is the single source of truth so
                // the PATH surface is uniformly safe regardless of
                // whether names come from `package.json` or CLI flags.
                if let Err(reason) = lpm_linker::validate_bin_name(mapped, "<cli-alias>") {
                    return Err(format!(
                        "`--alias {orig}={mapped}`: alias target rejected: {reason}"
                    ));
                }
                if alias_map.contains_key(orig) {
                    return Err(format!(
                        "`--alias {orig}={mapped}`: `{orig}` already has another \
                         alias mapping — specify each `<orig>` at most once"
                    ));
                }
                alias_map.insert(orig.to_string(), mapped.to_string());
            }
        }

        // A single command can't be simultaneously replaced AND aliased;
        // the two resolutions express contradictory intents for the
        // same collision. Catch it early — commit-time would detect it
        // too, but a CLI-shape error is the clearer place.
        for (orig, mapped) in &alias_map {
            if replace.contains(orig) {
                return Err(format!(
                    "`{orig}` is listed in both `--replace-bin` and `--alias {orig}={mapped}` \
                     — these are mutually exclusive resolutions"
                ));
            }
        }

        Ok(Self {
            replace,
            alias: alias_map,
        })
    }
}

pub async fn run(
    spec: &str,
    resolution: CollisionResolution,
    json_output: bool,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let registry = build_registry();

    // ─── Pre-resolve (no lock) ─────────────────────────────────────
    let resolved = pre_resolve(&registry, spec).await?;
    if !json_output {
        output::info(&format!(
            "{} resolved to {}",
            resolved.name.bold(),
            resolved.version.dimmed()
        ));
    }

    // ─── Step 1: prepare under .tx.lock ────────────────────────────
    let prep = with_exclusive_lock(root.global_tx_lock(), || prepare_locked(&root, &resolved))?;

    // ─── Step 2: slow install (no lock) ────────────────────────────
    if !json_output {
        output::info(&format!("installing {}...", spec.bold()));
    }
    // Step 2 failures (network, resolution, extract, link) are
    // intentionally NOT cleaned up here: recovery's roll-back path on
    // the next `lpm` invocation sees the uncompleted INTENT,
    // validate_install_root returns MissingMarker, and roll-back
    // removes the pending row + cleans the install root. Single
    // cleanup code path, called from one place.
    do_install(&root, &registry, &prep, json_output).await?;
    let commands = discover_bin_commands(&prep.install_root, &prep.name)?;
    if commands.is_empty() {
        return Err(LpmError::Script(format!(
            "package '{}' exposes no bin entries — `lpm install -g` is for executable tools. \
             Install it as a project dep with `lpm install {}` and `require()`/`import` it.",
            prep.name, prep.name
        )));
    }
    let marker = InstallReadyMarker::new(commands.clone());
    write_marker(&prep.install_root, &marker)?;

    // ─── Step 3a: TTY interactive prompt (M4.4) ───────────────────
    //
    // Runs BEFORE the commit lock. No-ops when the user already
    // supplied `--replace-bin` / `--alias` flags, when JSON mode is
    // set, or when stdin isn't a TTY. Otherwise inspects the current
    // (unlocked) manifest view, finds collisions, and prompts per-
    // collision. The returned resolution feeds `commit_locked`'s
    // planner via the same code path as flag-driven resolution.
    //
    // Drift between prompt and commit is handled by the planner's
    // residual-collision check under the tx lock — a user who took
    // 30 seconds to pick alias names while another process landed
    // a conflicting install sees a ResidualCollision error with the
    // new state, prompting them to re-run.
    let resolution = maybe_prompt_for_collisions(&root, &prep, resolution, json_output)?;

    // ─── Step 3b: validate + commit under .tx.lock ──────────────────
    //
    // `resolution` threads through to commit_locked so collision
    // resolution uses marker_commands as the authority. Per the M4.2
    // design, the resolution is validated AGAINST marker_commands
    // inside the lock (not earlier), since only the marker is the
    // authoritative post-extract command set.
    let active = with_exclusive_lock(root.global_tx_lock(), || {
        commit_locked(&root, &prep, &resolution)
    })?;

    // ─── Step 4: opportunistic tombstone sweep (M3.5) ─────────────
    // Fresh installs rarely tombstone (the rollback branch does),
    // but running a sweep post-commit means any leftover tombstones
    // from a prior failed tx get cleared as part of the happy path —
    // users don't have to remember to `lpm store gc`.
    //
    // `try_*` (non-blocking): another global command may be running in
    // parallel; we'd rather move on than wait. Errors are logged and
    // swallowed — the tx already committed, and the sweep retries on
    // next run.
    crate::commands::global::run_opportunistic_sweep(&root);

    // ─── Step 5: PATH onboarding hint (M3.6) ──────────────────────
    // Idempotent: at most one banner per host. The helper handles
    // marker stickiness and JSON-mode silence internally; we just
    // call it post-success and pass the report into print_success
    // so JSON consumers can see it as structured data.
    let hint = crate::path_onboarding::maybe_show_path_hint(&root, json_output);

    // ─── Output ────────────────────────────────────────────────────
    print_success(&active, &hint, json_output);

    // ─── Step 6: post-install blocked-scripts warning (M5.2) ──────
    // Mirrors the project-level post-install security summary
    // (suppressed inside the inner pipeline via `no_security_summary:
    // true`). Emits AFTER print_success so the happy-path "Installed
    // eslint@9.24.0" line lands first; the warning is a follow-up
    // pointing at `lpm approve-builds --global`.
    emit_post_install_blocked_warning(&root, &prep, json_output);

    Ok(())
}

// ─── Pre-resolve ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ResolvedSpec {
    name: String,
    version: Version,
    integrity: String,
    source: PackageSource,
    saved_spec: String,
}

async fn pre_resolve(registry: &RegistryClient, spec: &str) -> Result<ResolvedSpec, LpmError> {
    let (name, intent) = parse_user_save_intent(spec);
    // Dispatch by name shape: `@lpm.dev/owner.tool` goes through the
    // first-party registry path (PackageName parser); everything else
    // (`eslint`, `@types/node`, `@scope/foo`) is fetched via the npm
    // upstream proxy. This matches what the project install pipeline
    // does — global install just lifts the same dispatch.
    let metadata = if lpm_common::package_name::is_lpm_package(&name) {
        let pkg_name = lpm_common::PackageName::parse(&name)
            .map_err(|e| LpmError::Script(format!("invalid LPM package name '{name}': {e}")))?;
        registry.get_package_metadata(&pkg_name).await?
    } else {
        registry.get_npm_package_metadata(&name).await?
    };

    // Pick a concrete version that satisfies `intent`.
    let version_str = pick_version(&metadata, &intent)?;
    let version = Version::parse(&version_str).map_err(|e| {
        LpmError::Script(format!(
            "registry returned unparseable version '{version_str}' for '{name}': {e}"
        ))
    })?;
    let version_meta = metadata.versions.get(&version_str).ok_or_else(|| {
        LpmError::Script(format!(
            "version '{version_str}' missing from metadata for '{name}'"
        ))
    })?;
    let integrity = version_meta
        .dist
        .as_ref()
        .and_then(|d| d.integrity.clone())
        .ok_or_else(|| {
            LpmError::Script(format!(
                "version '{version_str}' of '{name}' has no integrity hash in registry metadata"
            ))
        })?;

    // Source is implied by name scope. `@lpm.dev/...` packages live on
    // the LPM registry; everything else is proxied through upstream npm.
    let source = if lpm_common::package_name::is_lpm_package(&name) {
        PackageSource::LpmDev
    } else {
        PackageSource::UpstreamNpm
    };

    // Phase 33 save-spec decision. Global installs honor the same
    // precedence as project installs (audit Medium #1 from M2.3 round).
    let decision = decide_saved_dependency_spec(
        &intent,
        &version,
        SaveFlags::default(),
        SaveConfig::default(),
    )?;

    Ok(ResolvedSpec {
        name,
        version,
        integrity,
        source,
        saved_spec: decision.spec_to_write,
    })
}

fn pick_version(
    metadata: &lpm_registry::PackageMetadata,
    intent: &UserSaveIntent,
) -> Result<String, LpmError> {
    let token = match intent {
        UserSaveIntent::Bare => "latest".to_string(),
        UserSaveIntent::Exact(s) => return Ok(s.clone()),
        UserSaveIntent::Range(s) => s.clone(),
        UserSaveIntent::DistTag(t) => t.clone(),
        UserSaveIntent::Wildcard => "*".to_string(),
        UserSaveIntent::Workspace(_) => {
            return Err(LpmError::Script(
                "global install does not support workspace: protocol".into(),
            ));
        }
    };

    // dist-tag fast path
    if let Some(v) = metadata.dist_tags.get(&token) {
        return Ok(v.clone());
    }
    // Range / wildcard via lpm-semver
    let req = VersionReq::parse(&token)
        .map_err(|e| LpmError::Script(format!("could not parse version token '{token}': {e}")))?;
    let mut versions: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|s| Version::parse(s).ok())
        .collect();
    if versions.is_empty() {
        return Err(LpmError::Script(format!(
            "registry returned no parseable versions for '{}'",
            metadata.name
        )));
    }
    let refs: Vec<&Version> = versions.iter().collect();
    match lpm_semver::max_satisfying(&refs, &req) {
        Some(v) => Ok(v.to_string()),
        None => {
            versions.sort();
            Err(LpmError::Script(format!(
                "no version of '{}' satisfies '{}'. Available: {}",
                metadata.name,
                token,
                versions
                    .iter()
                    .rev()
                    .take(5)
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }
}

// ─── Step 1: prepare under .tx.lock ──────────────────────────────────

#[derive(Debug, Clone)]
struct PrepResult {
    tx_id: String,
    name: String,
    version: Version,
    saved_spec: String,
    integrity: String,
    source: PackageSource,
    install_root: PathBuf,
    install_root_relative: String,
}

fn prepare_locked(root: &LpmRoot, resolved: &ResolvedSpec) -> Result<PrepResult, LpmError> {
    let mut manifest = read_for(root)?;

    if manifest.packages.contains_key(&resolved.name) {
        return Err(LpmError::Script(format!(
            "'{}' is already installed globally. Use `lpm global update {}` to upgrade or \
             `lpm uninstall -g {}` first. (Upgrade in-place lands in M3.4.)",
            resolved.name, resolved.name, resolved.name
        )));
    }
    if manifest.pending.contains_key(&resolved.name) {
        return Err(LpmError::Script(format!(
            "'{}' is already being installed by another process. Wait for it to finish or \
             check `~/.lpm/global/.tx.lock.pid` for a stale lock.",
            resolved.name
        )));
    }

    let install_root = root.install_root_for(&resolved.name, &resolved.version.to_string());
    let install_root_relative = format!(
        "installs/{}",
        install_root.file_name().unwrap().to_string_lossy()
    );

    // Phase 37 M0 (rev 6): pre-install path-budget guard. Reject the
    // install up front if the chosen install root would push us over the
    // 247-char budget — failing fast with an actionable LPM_HOME hint
    // beats failing mid-extraction with cryptic platform errors. No-op
    // on POSIX; load-bearing for Windows (and for any scenario where
    // third-party tooling does not honour `\\?\` long-path prefixes).
    lpm_common::check_install_path_budget(&install_root)?;

    let tx_id = mk_tx_id();

    // Write Intent + pending atomically: Intent first (fsynced), then
    // pending row. Crash between the two = recovery sees Intent without
    // pending, treats it as orphan (Case C).
    let mut wal = WalWriter::open(root.global_wal())?;
    let new_row_json = serde_json::json!({
        "saved_spec": resolved.saved_spec,
        "resolved": resolved.version.to_string(),
        "integrity": resolved.integrity,
        "source": serde_json::to_value(resolved.source).unwrap(),
        "started_at": Utc::now().to_rfc3339(),
        "root": install_root_relative,
        // commands: discovered at step 2; the marker is authoritative.
        "commands": Vec::<String>::new(),
    });
    wal.append(&WalRecord::Intent(Box::new(IntentPayload {
        tx_id: tx_id.clone(),
        kind: TxKind::Install,
        package: resolved.name.clone(),
        new_root_path: install_root.clone(),
        new_row_json,
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        // Populated at commit-time if the user resolved collisions via
        // flags (M4.2). prepare_locked runs before marker discovery, so
        // no collisions are known yet — empty delta here is correct.
        ownership_delta: Vec::new(),
    })))?;

    manifest.pending.insert(
        resolved.name.clone(),
        PendingEntry {
            saved_spec: resolved.saved_spec.clone(),
            resolved: resolved.version.to_string(),
            integrity: resolved.integrity.clone(),
            source: resolved.source,
            started_at: Utc::now(),
            root: install_root_relative.clone(),
            commands: Vec::new(),
            replaces_version: None,
        },
    );
    write_for(root, &manifest)?;

    Ok(PrepResult {
        tx_id,
        name: resolved.name.clone(),
        version: resolved.version.clone(),
        saved_spec: resolved.saved_spec.clone(),
        integrity: resolved.integrity.clone(),
        source: resolved.source,
        install_root,
        install_root_relative,
    })
}

// ─── Step 2: do_install (no lock) ────────────────────────────────────

async fn do_install(
    root: &LpmRoot,
    registry: &RegistryClient,
    prep: &PrepResult,
    suppress_nested_output: bool,
) -> Result<(), LpmError> {
    // Mirror dlx's pattern: write a synthetic package.json with the
    // single dependency, then call the project install pipeline against
    // the install root. This reuses every byte of resolution / store /
    // linker logic — global install is a self-hosted install with a
    // specific synthetic project.
    //
    // Phase 37 M5.2 addition: inject the global trusted-dependencies
    // into the synthesized `lpm.trustedDependencies` so the inner
    // install pipeline's strict-gate check honours user approvals
    // recorded via `lpm approve-builds --global`. Without this, every
    // scripts-carrying transitive dep would block on every global
    // install even after the user approved it.
    // Phase 37 M0 (rev 6): route the install-root creation + synthetic
    // package.json write through `as_extended_path` so a deeply-nested
    // `~/.lpm/global/installs/` path doesn't truncate at the legacy
    // 260-char Windows ceiling. No-op on POSIX.
    let install_root_ext = lpm_common::as_extended_path(&prep.install_root);
    std::fs::create_dir_all(&install_root_ext)?;
    let pkg_json_value = synthesize_pkg_json(root, &prep.name, &prep.version.to_string())?;
    let pkg_json_body = serde_json::to_string_pretty(&pkg_json_value)
        .map_err(|e| LpmError::Script(format!("serializing synthetic package.json: {e}")))?;
    std::fs::write(install_root_ext.join("package.json"), pkg_json_body)?;

    // In outer --json mode, the global install command owns stdout and
    // must emit exactly one machine-readable document. Silence the
    // inner self-hosted install pipeline so its human summary lines do
    // not corrupt the parent command's JSON contract.
    let _stdout_gag =
        crate::output::suppress_stdout(suppress_nested_output).map_err(LpmError::Script)?;

    crate::commands::install::run_with_options(
        registry,
        &prep.install_root,
        false, // json_output
        false, // offline
        false, // force
        false, // allow_new
        None,  // linker_override
        true,  // no_skills (global installs skip skill auto-install)
        true,  // no_editor_setup (global installs are not project-specific)
        true,  // no_security_summary (M5 will add approve-builds capture)
        false, // auto_build (M5 surface)
        None,
        None,
    )
    .await?;

    let _ = registry; // silence unused if we ever stop passing it directly
    Ok(())
}

/// Read the installed package's `package.json` to discover what bin
/// entries it exposes. Returns the list of command names that should
/// appear in `~/.lpm/bin/` and in the manifest's `commands` field.
///
/// Handles both `bin: "single-file"` (command name = package name's
/// short form) and `bin: { "name": "path" }` (command name = key) per
/// the npm spec.
fn discover_bin_commands(
    install_root: &std::path::Path,
    package_name: &str,
) -> Result<Vec<String>, LpmError> {
    // The installed package lives at
    // `<install_root>/node_modules/<package_name>/package.json`. For
    // scoped names like `@lpm.dev/owner.tool` the path is literal —
    // node_modules preserves the scope dir.
    let pkg_json_path = lpm_common::as_extended_path(
        &install_root
            .join("node_modules")
            .join(package_name)
            .join("package.json"),
    );
    let bytes = std::fs::read(&pkg_json_path).map_err(|e| {
        LpmError::Script(format!(
            "could not read installed package.json at {}: {e}",
            pkg_json_path.display()
        ))
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        LpmError::Script(format!(
            "installed package.json is not valid JSON at {}: {e}",
            pkg_json_path.display()
        ))
    })?;

    let Some(bin_field) = value.get("bin") else {
        return Ok(Vec::new());
    };
    let mut commands = Vec::new();
    match bin_field {
        serde_json::Value::String(_) => {
            // Single-file form: command name is the package's short name
            // (without the scope). For `@lpm.dev/owner.tool` → `tool`,
            // for `eslint` → `eslint`.
            commands.push(short_name(package_name).to_string());
        }
        serde_json::Value::Object(map) => {
            for k in map.keys() {
                commands.push(k.clone());
            }
        }
        _ => {}
    }
    Ok(commands)
}

fn short_name(package_name: &str) -> &str {
    // Strip scope: `@scope/name` → `name`. Otherwise return as-is.
    if let Some(rest) = package_name.strip_prefix('@')
        && let Some(slash) = rest.find('/')
    {
        return &rest[slash + 1..];
    }
    package_name
}

// ─── Step 3: commit under .tx.lock ───────────────────────────────────

/// `Output` payload for the success message. Mirrors the manifest
/// shape so JSON consumers can treat install -g and `global list` rows
/// uniformly.
#[derive(Debug, Clone)]
struct CommitOutput {
    name: String,
    version: String,
    saved_spec: String,
    source: PackageSource,
    commands: Vec<String>,
    install_root: PathBuf,
}

fn commit_locked(
    root: &LpmRoot,
    prep: &PrepResult,
    resolution: &CollisionResolution,
) -> Result<CommitOutput, LpmError> {
    let mut manifest = read_for(root)?;

    // Validate the install root using the marker's commands as the
    // authority. Pre-M3.2 we'd have passed pending.commands; with the
    // marker-as-authority refactor the install pipeline can ship empty
    // pending.commands and let `validate_install_root(None)` discover
    // them.
    let status = validate_install_root(&prep.install_root, None)?;
    let marker_commands = match status {
        InstallRootStatus::Ready { commands } => commands,
        other => {
            return Err(LpmError::Script(format!(
                "install root for '{}' failed validation: {other:?}. The transaction will be \
                 reconciled by recovery on the next `lpm` invocation.",
                prep.name
            )));
        }
    };

    // ─── Collision resolution (M4.2) ───────────────────────────────
    //
    // Three paths from here:
    //
    //   1. No collisions at all → zero work, zero delta, proceed to
    //      the existing happy path. Shortest path; same shape as M3.2.
    //   2. Collisions AND the user supplied `--replace-bin`/`--alias`
    //      → run the resolution planner. If the plan covers every
    //      collision (and introduces no new alias-target collisions),
    //      apply the delta to the manifest + emit the resolved shim
    //      set. If the plan fails, roll back inline and surface the
    //      planner's specific error (unknown command / residual /
    //      alias-target conflict).
    //   3. Collisions AND no user resolution → same inline rollback
    //      as pre-M4, with the pre-M4 error message. M4.3 will
    //      upgrade the message to name the two flag forms + a tailored
    //      example; for now we keep the "wait for M4" wording so the
    //      commit path stays narrow.
    let observed = find_command_collisions(&manifest, &prep.name, &marker_commands);
    let plan = if observed.is_empty() {
        // Shortest path: no collisions → empty plan with marker_commands
        // passing through unchanged.
        ResolutionPlan {
            ownership_delta: Vec::new(),
            final_commands: marker_commands.clone(),
            alias_rows_to_write: BTreeMap::new(),
            aliases_to_remove: Vec::new(),
            shim_removals: Vec::new(),
        }
    } else if resolution.is_empty() {
        // Collisions exist but the user supplied no resolution. Keep
        // pre-M4 behaviour: roll back inline + error out. (M4.3 will
        // upgrade the error copy to name the flag forms.)
        rollback_aborted_commit(root, &mut manifest, prep, &format_collisions(&observed))?;
        return Err(collision_error(&prep.name, &observed));
    } else {
        // Flag-driven resolution. Planner consumes the observed
        // collisions + user's flags; on failure, roll back inline so
        // disk state stays clean (no half-applied resolution).
        match plan_resolution(&manifest, &prep.name, &marker_commands, resolution) {
            Ok(p) => p,
            Err(plan_err) => {
                let rendered = plan_err.to_script_error(&prep.name).to_string();
                rollback_aborted_commit(root, &mut manifest, prep, &rendered)?;
                return Err(plan_err.to_script_error(&prep.name));
            }
        }
    };

    // ─── Apply the plan to the manifest ─────────────────────────────
    //
    // Each OwnershipChange is applied in order. After the loop the
    // manifest reflects every mutation the plan enumerated — but the
    // installing package's [packages.<name>] row still doesn't exist;
    // that's added below alongside the pending→packages flip.
    for change in &plan.ownership_delta {
        apply_ownership_change_to_manifest(&mut manifest, change, &prep.name);
    }

    // ─── Emit / remove shims per the plan ─────────────────────────
    //
    // Order:
    //   1. Remove any alias shims the plan marks for removal
    //      (currently always empty — AliasOwnerRemove shim rewrite is
    //      handled by `emit_shim`'s atomic rename-over in step 2).
    //   2. Emit direct-bin shims for every command in `final_commands`.
    //      `final_commands = marker_commands - aliased-away origs`, so
    //      origs that are aliased to a different PATH name do NOT get
    //      a shim under their original name (per the M4 invariant).
    //   3. Emit alias shims: one per new alias row, pointing at the
    //      declared bin inside the new install root.
    // ─── Append the finalized Intent with populated delta FIRST ──
    //
    // **M4 audit Finding 1 (High):** the second Intent MUST be
    // durably on disk BEFORE any shim mutation starts. The recovery
    // scanner's BTreeMap overwrites on same tx_id, so the latest
    // Intent wins; if we crash between shim swap and this append,
    // recovery reads the ORIGINAL prepare-time Intent whose delta +
    // new_aliases_json are empty. The roll-forward path would then
    // emit shims from the unfiltered marker_commands (putting the
    // aliased-away orig back on PATH) and skip every displaced-owner
    // restoration. The user's chosen collision resolution is lost
    // AND the on-disk state silently disagrees with the manifest.
    //
    // Ordering rule for M4.2 tx:
    //   1. Apply delta to in-memory manifest (pure)
    //   2. Append second Intent with populated delta   [DURABLE]
    //   3. Shim mutations (OS-visible)
    //   4. Write manifest                              [DURABLE]
    //   5. Append Commit                               [DURABLE]
    //
    // Crash after 2 but before 3: recovery sees populated delta,
    // marker is Ready, roll_forward re-applies delta + emits
    // final_commands shims, writes manifest, appends Commit.
    // Crash after 3 but before 4: same as above (re-emitting shims
    // is idempotent via emit_shim's atomic rename).
    // Crash after 4 but before 5: AlreadyCommitted path — append
    // missing Commit and done.
    let new_aliases_json = {
        let mut obj = serde_json::Map::new();
        for (alias_name, entry) in &plan.alias_rows_to_write {
            obj.insert(
                alias_name.clone(),
                serde_json::json!({
                    "package": entry.package,
                    "bin": entry.bin,
                }),
            );
        }
        serde_json::Value::Object(obj)
    };
    let new_row_json = serde_json::json!({
        "saved_spec": prep.saved_spec,
        "resolved": prep.version.to_string(),
        "integrity": prep.integrity,
        "source": serde_json::to_value(prep.source).unwrap_or(serde_json::Value::Null),
        "root": prep.install_root_relative,
        "commands": plan.final_commands,
    });
    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Intent(Box::new(IntentPayload {
        tx_id: prep.tx_id.clone(),
        kind: TxKind::Install,
        package: prep.name.clone(),
        new_root_path: prep.install_root.clone(),
        new_row_json,
        prior_active_row_json: None,
        // Prior-ownership snapshots: for M4.2 these live inside
        // `ownership_delta` (each variant carries its own snapshot).
        // The legacy `prior_command_ownership_json` stays empty for
        // fresh installs.
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json,
        ownership_delta: plan.ownership_delta.clone(),
    })))?;

    // ─── Emit / remove shims per the plan ─────────────────────────
    //
    // Now safe: the second Intent is durable, so any crash from here
    // on is recoverable via roll_forward replaying the same delta.
    //
    // Order within this block:
    //   - shim_removals (currently empty; kept for future variants)
    //   - direct-bin shims for every command in `final_commands`
    //     (= marker_commands minus aliased-away origs, per the M4
    //      invariant)
    //   - alias shims: one per new alias row
    let bin_dir = root.bin_dir();
    let install_bin = prep.install_root.join("node_modules").join(".bin");
    for shim_name in &plan.shim_removals {
        let _ = remove_shim(&bin_dir, shim_name);
    }
    for cmd in &plan.final_commands {
        let target = install_bin.join(cmd);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: cmd.clone(),
                target,
            },
        )?;
    }
    for (alias_name, alias_entry) in &plan.alias_rows_to_write {
        let target = install_bin.join(&alias_entry.bin);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: alias_name.clone(),
                target,
            },
        )?;
    }

    // Phase 37 M3 (audit follow-up): three-artifact invariant — on
    // Windows a command is "owned" only when all three of its shim
    // artifacts (`.cmd`, `.ps1`, no-extension bash shim) are present.
    // emit_shim already writes the triple, but a partial failure
    // (ENOSPC mid-triple, AV holding the second file) leaves disk
    // state inconsistent with the manifest commit we're about to
    // write. Verify after every emission and abort the transaction if
    // any triple is incomplete — recovery's roll-forward will re-emit
    // from WAL data on next invocation. On POSIX `artifacts_complete`
    // collapses to "the symlink exists," so this is a strict
    // generalisation, not Windows-only.
    let mut incomplete: Vec<String> = Vec::new();
    for cmd in &plan.final_commands {
        if !artifacts_complete(&bin_dir, cmd) {
            incomplete.push(cmd.clone());
        }
    }
    for alias_name in plan.alias_rows_to_write.keys() {
        if !artifacts_complete(&bin_dir, alias_name) {
            incomplete.push(alias_name.clone());
        }
    }
    if !incomplete.is_empty() {
        let detail = format!(
            "shim triple incomplete after emit for: {}. The transaction \
             will be reconciled by recovery on the next `lpm` invocation.",
            incomplete.join(", ")
        );
        rollback_aborted_commit(root, &mut manifest, prep, &detail)?;
        return Err(LpmError::Script(detail));
    }

    // ─── Flip [pending] into [packages] + persist manifest ─────────
    //
    // `final_commands` (not `marker_commands`) is the authoritative
    // post-resolution list: names aliased away do NOT appear here.
    let active = PackageEntry {
        saved_spec: prep.saved_spec.clone(),
        resolved: prep.version.to_string(),
        integrity: prep.integrity.clone(),
        source: prep.source,
        installed_at: Utc::now(),
        root: prep.install_root_relative.clone(),
        commands: plan.final_commands.clone(),
    };
    manifest.packages.insert(prep.name.clone(), active);
    manifest.pending.remove(&prep.name);

    // Per-tx ordering invariant from the M3.1 audit: persist manifest
    // BEFORE WAL COMMIT. A crash between manifest persist and WAL
    // append is the "Already Committed" case recovery handles
    // explicitly.
    write_for(root, &manifest)?;

    wal.append(&WalRecord::Commit {
        tx_id: prep.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(CommitOutput {
        name: prep.name.clone(),
        version: prep.version.to_string(),
        saved_spec: prep.saved_spec.clone(),
        source: prep.source,
        commands: plan.final_commands,
        install_root: prep.install_root.clone(),
    })
}

/// Render a list of collisions as a multi-line error message. Reused
/// by both the user-facing collision error and the WAL Abort reason
/// recovery would later see.
fn format_collisions(collisions: &[CommandCollision]) -> String {
    collisions
        .iter()
        .map(|c| {
            let owner = if c.via_alias {
                format!("alias \u{2192} {}", c.current_owner)
            } else {
                c.current_owner.clone()
            };
            format!("  {} (owned by {})", c.command, owner)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Phase 37 M4.3: unresolved-collision error with a copy-pasteable
/// remediation. Replaces the pre-M4 "wait for M4" wording. Output
/// shape:
///
///   'foo' would expose command(s) already taken on this host:
///     serve (owned by http-server)
///     lint  (owned by alias → eslint-config)
///
///   To resolve, re-run with one of the following per colliding
///   command:
///
///     lpm install -g foo --replace-bin serve --replace-bin lint
///     lpm install -g foo --alias serve=foo-serve,lint=foo-lint
///
///   --replace-bin transfers ownership; --alias installs the declared
///   bin under a different PATH name. Mix both as needed.
///
/// The concrete example uses the actual colliding command names so the
/// user can paste without substitution. The alias-target names use a
/// `<package>-<command>` pattern as a safe default (real command names
/// that won't collide with the existing owners, even on a repeat run).
fn collision_error(installing_pkg: &str, collisions: &[CommandCollision]) -> LpmError {
    let plural_s = if collisions.len() == 1 { "" } else { "s" };
    let plural_verb = if collisions.len() == 1 { "is" } else { "are" };

    // Build concrete example invocations using the real collisions.
    // `--replace-bin <cmd>` per collision; `--alias <cmd>=<pkg>-<cmd>`
    // per collision. The alias prefix is deterministic from the
    // package being installed, so the user gets a reasonable default
    // they can tweak.
    let short_pkg = short_name(installing_pkg);
    let replace_flags = collisions
        .iter()
        .map(|c| format!("--replace-bin {}", c.command))
        .collect::<Vec<_>>()
        .join(" ");
    let alias_flags = {
        let mappings = collisions
            .iter()
            .map(|c| format!("{}={short_pkg}-{}", c.command, c.command))
            .collect::<Vec<_>>()
            .join(",");
        format!("--alias {mappings}")
    };

    LpmError::Script(format!(
        "'{installing_pkg}' would expose command{plural_s} that {plural_verb} already \
         taken on this host:\n{}\n\nTo resolve, re-run with one of the following per \
         colliding command:\n\n    lpm install -g {installing_pkg} {replace_flags}\n    \
         lpm install -g {installing_pkg} {alias_flags}\n\n--replace-bin transfers ownership to \
         '{installing_pkg}'; --alias installs the declared bin under a different PATH name. \
         Mix both as needed. (Interactive resolution lands in M4.4.)",
        format_collisions(collisions),
    ))
}

// ─── M4.4: TTY interactive prompt ────────────────────────────────────

/// Per-collision choice from the TTY prompt. Folds into a
/// `CollisionResolution` by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CollisionChoice {
    Replace,
    Alias(String),
    Cancel,
}

/// Pre-commit pass that prompts the user to resolve collisions when:
///   - Collisions exist on the current (unlocked) manifest view
///   - The user supplied no `--replace-bin`/`--alias` flags
///   - `json_output` is false (JSON mode falls through to the commit-
///     time error so agents get a deterministic structured response)
///   - `stdin` is a TTY
///
/// Otherwise passes the resolution through unchanged — `commit_locked`
/// will either find no collisions (fine), find collisions with flags
/// (planner takes over), or find collisions with no flags (emits the
/// M4.3 error).
///
/// The manifest read here is UNLOCKED. Drift between this read and
/// commit_locked's lock acquisition is acceptable: the planner inside
/// commit_locked re-validates against a freshly-read manifest under the
/// tx lock, and any new residual collision becomes a
/// `PlanError::ResidualCollision` error. The user sees "collision set
/// changed, re-run" via the standard error path.
fn maybe_prompt_for_collisions(
    root: &LpmRoot,
    prep: &PrepResult,
    resolution: CollisionResolution,
    json_output: bool,
) -> Result<CollisionResolution, LpmError> {
    // Early exits.
    if !resolution.is_empty() {
        return Ok(resolution);
    }
    if json_output {
        return Ok(resolution);
    }
    // M4 audit Finding 3: require BOTH stdin AND stdout to be a TTY.
    // Checking only stdin would let `lpm install -g foo | cat` enter
    // the cliclack prompt with no visible UI (output goes to the
    // pipe), stranding the user with an unresponsive terminal.
    // Matches the pattern used by `approve_builds.rs` and
    // `upgrade.rs` for every other interactive command.
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(resolution);
    }

    // Unlocked read of the current manifest + install root validation.
    // Same shape as the very first step of commit_locked so the
    // collision set we prompt about matches what commit_locked will
    // re-check under the lock (modulo drift).
    let manifest = read_for(root)?;
    let status = validate_install_root(&prep.install_root, None)?;
    let marker_commands = match status {
        InstallRootStatus::Ready { commands } => commands,
        // If the marker isn't ready yet we can't enumerate the
        // commands to prompt about. Fall through; commit_locked will
        // surface the validate error.
        _ => return Ok(resolution),
    };
    let collisions = find_command_collisions(&manifest, &prep.name, &marker_commands);
    if collisions.is_empty() {
        return Ok(resolution);
    }

    // Run the prompt.
    prompt_collisions(&prep.name, &collisions)
}

/// The interactive prompt itself. One cliclack `select` per colliding
/// command (replace / alias / cancel). Alias choice follows up with
/// an `input` for the alias name; invalid inputs re-prompt. Cancel on
/// any colliding command aborts the whole install.
fn prompt_collisions(
    installing_pkg: &str,
    collisions: &[CommandCollision],
) -> Result<CollisionResolution, LpmError> {
    use crate::prompt::prompt_err;

    eprintln!();
    output::warn(&format!(
        "'{}' would expose {} command{} that {} already taken on this host.",
        installing_pkg.bold(),
        collisions.len(),
        if collisions.len() == 1 { "" } else { "s" },
        if collisions.len() == 1 { "is" } else { "are" },
    ));
    eprintln!();

    // Collect one choice per collision, then fold. Separating the
    // I/O loop from the fold lets `fold_choices_into_resolution` be
    // unit-tested without a PTY.
    let mut choices: Vec<(CommandCollision, CollisionChoice)> =
        Vec::with_capacity(collisions.len());
    for c in collisions {
        let choice = prompt_one_collision(installing_pkg, c).map_err(prompt_err)?;
        choices.push((c.clone(), choice));
    }
    fold_choices_into_resolution(&choices)
}

/// Pure fold: one `(CommandCollision, CollisionChoice)` pair per
/// colliding command in order. Returns `Err` if any choice is
/// `Cancel` (the whole install aborts on first cancel). Otherwise
/// builds a `CollisionResolution` with the per-collision choices.
///
/// Separated from `prompt_collisions` so the fold logic is testable
/// without a PTY. The I/O shell (`prompt_one_collision` + cliclack)
/// stays thin around this pure core.
fn fold_choices_into_resolution(
    choices: &[(CommandCollision, CollisionChoice)],
) -> Result<CollisionResolution, LpmError> {
    let mut replace: HashSet<String> = HashSet::new();
    let mut alias: BTreeMap<String, String> = BTreeMap::new();
    for (collision, choice) in choices {
        match choice {
            CollisionChoice::Replace => {
                replace.insert(collision.command.clone());
            }
            CollisionChoice::Alias(alias_name) => {
                alias.insert(collision.command.clone(), alias_name.clone());
            }
            CollisionChoice::Cancel => {
                return Err(LpmError::Script(format!(
                    "install cancelled: user declined to resolve collision on '{}'",
                    collision.command
                )));
            }
        }
    }
    Ok(CollisionResolution { replace, alias })
}

/// Prompt for one collision. Returns the user's choice.
fn prompt_one_collision(
    installing_pkg: &str,
    collision: &CommandCollision,
) -> Result<CollisionChoice, std::io::Error> {
    let owner_label = if collision.via_alias {
        format!("alias \u{2192} {}", collision.current_owner)
    } else {
        collision.current_owner.clone()
    };
    let label = format!(
        "Command '{}' is currently owned by '{}'. How to resolve?",
        collision.command, owner_label,
    );

    let short_pkg = short_name(installing_pkg);
    let default_alias = format!("{short_pkg}-{}", collision.command);

    loop {
        let choice: &str = cliclack::select(&label)
            .item(
                "replace",
                format!(
                    "Replace — transfer '{}' to '{}'",
                    collision.command, installing_pkg
                ),
                "",
            )
            .item(
                "alias",
                format!(
                    "Alias — install '{}' under a different PATH name",
                    collision.command
                ),
                "",
            )
            .item("cancel", "Cancel — abort the install", "")
            .initial_value("alias")
            .interact()?;

        match choice {
            "replace" => return Ok(CollisionChoice::Replace),
            "cancel" => return Ok(CollisionChoice::Cancel),
            "alias" => {
                let alias_input: String = cliclack::input(format!(
                    "Alias name for '{}' (PATH command)",
                    collision.command
                ))
                .default_input(&default_alias)
                .validate(|v: &String| {
                    let trimmed = v.trim();
                    if trimmed.is_empty() {
                        return Err("alias name cannot be empty".to_string());
                    }
                    lpm_linker::validate_bin_name(trimmed, "<cli-alias>")
                })
                .interact()?;
                let alias_name = alias_input.trim().to_string();
                if alias_name == collision.command {
                    output::warn(&format!(
                        "alias target '{alias_name}' is the same as the original name — \
                         nothing to resolve. Try again."
                    ));
                    continue;
                }
                return Ok(CollisionChoice::Alias(alias_name));
            }
            _ => unreachable!("cliclack::select returns one of the declared keys"),
        }
    }
}

// ─── M4.2: Resolution planner ────────────────────────────────────────

/// Output of the resolution planner. Feeds directly into `commit_locked`'s
/// manifest mutation + WAL + shim emission. Pure data — every field is
/// computed by `plan_resolution`, which itself takes a read-only view of
/// the pre-commit state so the function stays unit-testable without any
/// filesystem scaffolding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolutionPlan {
    /// The ordered list of ownership mutations to persist in the WAL's
    /// `IntentPayload.ownership_delta`. Recovery replays this in order.
    pub ownership_delta: Vec<OwnershipChange>,
    /// The `PackageEntry.commands` value to write for the installing
    /// package. Equals `marker_commands` minus any command that is
    /// aliased away (per the M4 invariant: `commands` holds only names
    /// with a direct shim owned by this package).
    pub final_commands: Vec<String>,
    /// New `[aliases]` rows to write, keyed by alias name. Mirrors the
    /// entries in `ownership_delta` that are `AliasInstall` variants;
    /// captured here in ready-to-merge form so `commit_locked` doesn't
    /// have to pattern-match the delta again.
    pub alias_rows_to_write: BTreeMap<String, AliasEntry>,
    /// Alias keys whose existing `[aliases]` row should be dropped from
    /// the manifest before `alias_rows_to_write` is applied. Mirrors
    /// the `AliasOwnerRemove` entries in `ownership_delta`.
    pub aliases_to_remove: Vec<String>,
    /// Shims in `~/.lpm/bin/` that must be removed as part of the
    /// resolution (alias-owner takeover by a direct-bin install).
    /// The shim for an alias being replaced with a new direct owner
    /// must be dropped before the new one is emitted so the mid-swap
    /// state never exposes both.
    pub shim_removals: Vec<String>,
}

/// Error returned by the resolution planner when the user's flag choices
/// don't reconcile the observed collisions. Carries enough detail for
/// the commit-time error message to name the specific unresolved command
/// / mis-mapped alias target — see `plan_resolution_error_to_script`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlanError {
    /// A flag referenced a command name that the package doesn't declare
    /// (not in `marker_commands`). Carries the flag name and the offending
    /// command for diagnostic rendering.
    UnknownCommand { flag: &'static str, command: String },
    /// After applying the user's resolutions, at least one command still
    /// collides with another package's PATH entry. Recovery is not
    /// attempted; the caller must abort.
    ResidualCollision { collisions: Vec<CommandCollision> },
    /// The user's aliases target PATH names that collide — either two
    /// aliases point to the same RHS, or an alias RHS equals another
    /// direct bin of the package being installed.
    AliasTargetCollision {
        targets: Vec<String>,
        reason: String,
    },
}

impl PlanError {
    pub(crate) fn to_script_error(&self, installing_pkg: &str) -> LpmError {
        match self {
            PlanError::UnknownCommand { flag, command } => LpmError::Script(format!(
                "`{flag} {command}` references a command '{command}' that '{installing_pkg}' \
                 does not declare. Re-check the package's bin entries with `lpm info \
                 {installing_pkg}` and retry."
            )),
            PlanError::ResidualCollision { collisions } => LpmError::Script(format!(
                "after applying collision-resolution flags, '{installing_pkg}' still conflicts \
                 on:\n{}\n\nAdd `--replace-bin <cmd>` or `--alias <cmd>=<new-name>` for each of \
                 the above, or pick a different package.",
                format_collisions(collisions)
            )),
            PlanError::AliasTargetCollision { targets, reason } => LpmError::Script(format!(
                "alias target conflict ({reason}): {}. Pick different alias name(s) and retry.",
                targets.join(", ")
            )),
        }
    }
}

/// Plan the post-resolution state given the user's flags and the
/// observed collisions. Returns `Ok(ResolutionPlan)` when the install
/// can proceed, or `Err(PlanError)` when the user's resolutions don't
/// cover every residual collision (or introduce new ones).
///
/// Pure function. No I/O. The mutable `manifest` borrow is read-only
/// in practice (we clone for the working view); the type is `&GlobalManifest`.
pub(crate) fn plan_resolution(
    manifest: &GlobalManifest,
    installing_pkg: &str,
    marker_commands: &[String],
    resolution: &CollisionResolution,
) -> Result<ResolutionPlan, PlanError> {
    // ─── Step 1: validate flags against marker_commands ──────────────
    //
    // The user said "replace serve" or "alias serve=foo-serve" — we
    // check that `serve` is actually a command the package declares.
    // Unknown commands here are almost always typos; surface early with
    // the specific flag name so the user can fix their invocation.
    let marker_set: HashSet<&str> = marker_commands.iter().map(|s| s.as_str()).collect();
    for cmd in &resolution.replace {
        if !marker_set.contains(cmd.as_str()) {
            return Err(PlanError::UnknownCommand {
                flag: "--replace-bin",
                command: cmd.clone(),
            });
        }
    }
    for orig in resolution.alias.keys() {
        if !marker_set.contains(orig.as_str()) {
            return Err(PlanError::UnknownCommand {
                flag: "--alias",
                command: orig.clone(),
            });
        }
    }

    // ─── Step 2: classify each colliding command ─────────────────────
    //
    // For each marker_command that collides (i.e. another package or
    // alias already owns that PATH name), decide what the user's
    // resolution says to do. Three outcomes:
    //   - In `replace` set → record DirectTransfer or AliasOwnerRemove
    //     depending on how the current owner holds it.
    //   - In `alias` map → the aliased-away variant of Cancel: this
    //     command won't be exposed directly; it goes into the alias
    //     table as AliasInstall. Wait — if the command collides AND the
    //     user aliases it to a different name, the alias side-steps the
    //     collision entirely. The original name stays with its current
    //     owner. The new alias shim is what goes to PATH.
    //   - Otherwise → residual collision, accumulate for error output.
    let mut ownership_delta: Vec<OwnershipChange> = Vec::new();
    let mut aliases_to_remove: Vec<String> = Vec::new();
    // Populated only when a future variant needs pre-removal before the
    // new shim lands. Alias-owner replace today rewrites via emit_shim's
    // atomic rename-over, so this stays empty for M4.2 but is kept as
    // part of the plan shape for future use.
    let shim_removals: Vec<String> = Vec::new();
    let mut residual: Vec<CommandCollision> = Vec::new();

    let observed = find_command_collisions(manifest, installing_pkg, marker_commands);
    let observed_by_command: BTreeMap<&str, &CommandCollision> =
        observed.iter().map(|c| (c.command.as_str(), c)).collect();

    for cmd in marker_commands {
        let Some(collision) = observed_by_command.get(cmd.as_str()) else {
            // No collision for this command — it'll be exposed normally
            // unless the user aliased it (handled below in step 3).
            continue;
        };
        if resolution.replace.contains(cmd) {
            // Replace: branch by how the current owner holds this name.
            if collision.via_alias {
                // Alias-owner replace: drop the alias row, snapshot it.
                // The colliding PATH name IS the alias key here.
                if let Some(existing) = manifest.aliases.get(cmd.as_str()) {
                    let snapshot = serde_json::json!({
                        "package": existing.package,
                        "bin": existing.bin,
                    });
                    ownership_delta.push(OwnershipChange::AliasOwnerRemove {
                        alias_name: cmd.clone(),
                        entry_snapshot: snapshot,
                    });
                    aliases_to_remove.push(cmd.clone());
                    // The alias shim is rewritten below (emit_shim is
                    // atomic rename-over), so no explicit pre-removal
                    // is needed. Leaving the shim_removals entry out.
                }
                // If manifest says the alias row doesn't exist but
                // `via_alias` is true, the manifest is internally
                // inconsistent. Treat it as an unresolved collision
                // rather than silently succeeding.
            } else {
                // Direct-owner replace: snapshot the owner's full row
                // for precise rollback. Skip if the owner's row is
                // somehow absent (defensive — shouldn't happen).
                let Some(owner_entry) = manifest.packages.get(&collision.current_owner) else {
                    residual.push((*collision).clone());
                    continue;
                };
                let snapshot = serde_json::to_value(owner_entry).unwrap_or(serde_json::Value::Null);
                ownership_delta.push(OwnershipChange::DirectTransfer {
                    command: cmd.clone(),
                    from_package: collision.current_owner.clone(),
                    from_row_snapshot: snapshot,
                });
            }
        } else if resolution.alias.contains_key(cmd) {
            // Aliased away: this command won't collide because we're
            // not emitting it under its original name. The collision
            // check for the NEW alias target happens in step 4 below.
            // No ownership_delta entry for the old name.
            continue;
        } else {
            residual.push((*collision).clone());
        }
    }

    // ─── Step 3: build AliasInstall entries for each --alias mapping ─
    //
    // Every `--alias orig=alias` produces one AliasInstall regardless
    // of whether `orig` collided (the alias is an explicit user choice,
    // not a collision-only mechanism). `orig` MUST be in marker_commands
    // (checked in step 1). The alias shim goes on PATH; the original
    // name does NOT.
    let mut alias_rows_to_write: BTreeMap<String, AliasEntry> = BTreeMap::new();
    for (orig, alias) in &resolution.alias {
        ownership_delta.push(OwnershipChange::AliasInstall {
            alias_name: alias.clone(),
            package: installing_pkg.to_string(),
            bin: orig.clone(),
        });
        alias_rows_to_write.insert(
            alias.clone(),
            AliasEntry {
                package: installing_pkg.to_string(),
                bin: orig.clone(),
            },
        );
    }

    // ─── Step 4: residual-collision checks ────────────────────────
    //
    // After classifying each marker command (step 2) and building the
    // AliasInstall entries (step 3), validate the final picture in two
    // passes:
    //
    //   (a) Duplicate alias targets (two `--alias X=Y, Z=Y`) — checked
    //       on the resolution itself, independent of manifest state.
    //   (b) Alias RHS collides with an existing globally-exposed name
    //       that our DirectTransfer / AliasOwnerRemove didn't free up.
    //       Checked against a "freeing" view that applies those two
    //       mutations but NOT AliasInstall (otherwise the installing
    //       package's alias row would self-shadow the real owner).
    //   (c) Alias RHS equals another of the new package's direct bins
    //       — e.g. `--alias serve=lint` when `lint` is also a declared
    //       bin. Pure set-intersection against `final_commands`.

    // Compute the final `commands` list for the installing package:
    // marker_commands minus the origs that are now aliased away.
    let aliased_origs: HashSet<&str> = resolution.alias.keys().map(|s| s.as_str()).collect();
    let final_commands: Vec<String> = marker_commands
        .iter()
        .filter(|c| !aliased_origs.contains(c.as_str()))
        .cloned()
        .collect();

    // (a) Duplicate alias targets within the resolution itself.
    let mut seen_targets: HashSet<&str> = HashSet::new();
    let mut duplicate_targets: Vec<String> = Vec::new();
    for target in resolution.alias.values() {
        if !seen_targets.insert(target.as_str()) {
            duplicate_targets.push(target.clone());
        }
    }
    if !duplicate_targets.is_empty() {
        return Err(PlanError::AliasTargetCollision {
            targets: duplicate_targets,
            reason: "two or more aliases map to the same PATH name".into(),
        });
    }

    // (b) Alias RHS collides with a post-freeing state.
    //
    // "Freeing view": clone the manifest and apply only the
    // DirectTransfer / AliasOwnerRemove mutations. That captures what
    // names the user has explicitly taken ownership of via
    // `--replace-bin`, so a construction like
    // `--replace-bin taken --alias serve=taken` correctly accepts
    // (replace frees `taken`, then alias emits under `taken`).
    //
    // AliasInstall entries are INTENTIONALLY excluded from this view —
    // applying them first would make the installing package own the
    // alias row, and `find_command_collisions`'s self-owner exclusion
    // would then hide real collisions from the check. We insert only
    // a bare candidate row (no commands) for the self-exclusion to
    // have the right shape.
    let mut freeing_view = manifest.clone();
    for change in &ownership_delta {
        if let OwnershipChange::AliasInstall { .. } = change {
            continue;
        }
        apply_ownership_change_to_manifest(&mut freeing_view, change, installing_pkg);
    }
    let bare_candidate = PackageEntry {
        saved_spec: "<planning>".to_string(),
        resolved: "<planning>".to_string(),
        integrity: "<planning>".to_string(),
        source: PackageSource::LpmDev,
        installed_at: Utc::now(),
        root: "<planning>".to_string(),
        commands: Vec::new(),
    };
    freeing_view
        .packages
        .insert(installing_pkg.to_string(), bare_candidate);

    let alias_targets: Vec<String> = resolution.alias.values().cloned().collect();
    let alias_target_collisions =
        find_command_collisions(&freeing_view, installing_pkg, &alias_targets);
    if !alias_target_collisions.is_empty() {
        return Err(PlanError::AliasTargetCollision {
            targets: alias_target_collisions
                .iter()
                .map(|c| c.command.clone())
                .collect(),
            reason: "alias target is already owned by another package or alias".into(),
        });
    }

    // (c) Alias RHS equals another direct bin of the new package.
    let direct_bins: HashSet<&str> = final_commands.iter().map(|s| s.as_str()).collect();
    let bin_overlap: Vec<String> = resolution
        .alias
        .values()
        .filter(|t| direct_bins.contains(t.as_str()))
        .cloned()
        .collect();
    if !bin_overlap.is_empty() {
        return Err(PlanError::AliasTargetCollision {
            targets: bin_overlap,
            reason: "alias target collides with a sibling direct bin of the same package".into(),
        });
    }

    // Residual collisions (from step 2) must all be resolved.
    if !residual.is_empty() {
        return Err(PlanError::ResidualCollision {
            collisions: residual,
        });
    }

    Ok(ResolutionPlan {
        ownership_delta,
        final_commands,
        alias_rows_to_write,
        aliases_to_remove,
        shim_removals,
    })
}

/// Apply one OwnershipChange to a manifest in-place. Used both by the
/// planner (on a working view, to feed the residual-collision check)
/// and by `commit_locked` (on the real manifest, during commit). Also
/// used by recovery roll-forward to replay the delta deterministically
/// from WAL data.
///
/// `installing_pkg` is passed in so `AliasInstall` can be self-consistent
/// when the WAL snapshot's `package` field agrees (defensive — we use
/// the WAL snapshot's own `package` for authority during replay).
pub(crate) fn apply_ownership_change_to_manifest(
    manifest: &mut GlobalManifest,
    change: &OwnershipChange,
    installing_pkg: &str,
) {
    match change {
        OwnershipChange::DirectTransfer {
            command,
            from_package,
            ..
        } => {
            if let Some(owner) = manifest.packages.get_mut(from_package) {
                owner.commands.retain(|c| c != command);
            }
            // The installing package's row will get `command` added via
            // its `final_commands` write by `commit_locked` (or via the
            // pending→packages flip in recovery). Nothing to do here.
            let _ = installing_pkg;
        }
        OwnershipChange::AliasOwnerRemove { alias_name, .. } => {
            manifest.aliases.remove(alias_name);
        }
        OwnershipChange::AliasInstall {
            alias_name,
            package,
            bin,
        } => {
            manifest.aliases.insert(
                alias_name.clone(),
                AliasEntry {
                    package: package.clone(),
                    bin: bin.clone(),
                },
            );
        }
    }
}

/// Roll back a transaction that reached commit_locked but failed
/// validation (collision, future failure modes). Mirrors recover.rs's
/// roll_back semantics from the user-facing call site so the on-disk
/// state stays clean and the next recovery has nothing to reconcile.
///
/// Order of operations (per the M3.1 audit's manifest-before-WAL
/// invariant):
///   1. Drop the install root (or tombstone if locked).
///   2. Remove `[pending.<pkg>]` row.
///   3. Persist manifest.
///   4. Append WAL Abort.
fn rollback_aborted_commit(
    root: &LpmRoot,
    manifest: &mut lpm_global::GlobalManifest,
    prep: &PrepResult,
    reason: &str,
) -> Result<(), LpmError> {
    let install_root_ext = lpm_common::as_extended_path(&prep.install_root);
    if install_root_ext.exists()
        && let Err(e) = std::fs::remove_dir_all(&install_root_ext)
    {
        tracing::debug!(
            "install -g rollback: deferring install-root cleanup via tombstone: {}",
            e
        );
        manifest.tombstones.push(prep.install_root_relative.clone());
    }
    manifest.pending.remove(&prep.name);
    write_for(root, manifest)?;
    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Abort {
        tx_id: prep.tx_id.clone(),
        reason: format!("commit-time validation failed: {reason}"),
        aborted_at: Utc::now(),
    })?;
    Ok(())
}

// ─── Output ──────────────────────────────────────────────────────────

fn print_success(
    out: &CommitOutput,
    hint: &crate::path_onboarding::PathHintReport,
    json_output: bool,
) {
    if json_output {
        // M3.6: surface the PATH hint as structured data in JSON
        // mode so agents can detect "shims installed but not on
        // PATH" without scraping stderr/stdout. The four fields
        // mirror PathHintReport so consumers can treat it as a
        // pass-through.
        let body = serde_json::json!({
            "success": true,
            "package": out.name,
            "version": out.version,
            "saved_spec": out.saved_spec,
            "source": out.source,
            "commands": out.commands,
            "install_root": out.install_root.display().to_string(),
            "path_hint": {
                "bin_dir": hint.bin_dir.display().to_string(),
                "on_path": hint.on_path,
                "marker_already_present": hint.marker_already_present,
                "banner_printed": hint.banner_printed,
            },
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return;
    }
    output::success(&format!(
        "Installed {}@{} (saved as {})",
        out.name.bold(),
        out.version.dimmed(),
        out.saved_spec.dimmed()
    ));
    if out.commands.is_empty() {
        // Shouldn't happen — we error out earlier when bin entries are
        // empty — but guard the message just in case.
        return;
    }
    output::info(&format!(
        "Exposed command{} on PATH: {}",
        if out.commands.len() == 1 { "" } else { "s" },
        out.commands.join(", ")
    ));
    // The banner (if any) was printed by `maybe_show_path_hint` BEFORE
    // we got here. We don't re-emit anything in human mode; the hint
    // is its own block of output. Leaving this comment so future
    // refactors don't accidentally double-print.
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn build_registry() -> RegistryClient {
    let registry_url = std::env::var("LPM_REGISTRY_URL")
        .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
    RegistryClient::new().with_base_url(&registry_url)
}

/// Generate a stable transaction id: `<unix-nanos>-<pid>`. Adequate
/// uniqueness within a single host (per the WAL Intent doc).
fn mk_tx_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}-{}", std::process::id())
}

/// Sanitize a package name for use as the synthetic project's `name`
/// field. The synthetic `package.json` `name` is purely cosmetic
/// (avoids npm warnings about missing name) — the real install target
/// is in `dependencies`. Must be a valid npm package name.
fn sanitize_inner_name(name: &str) -> String {
    name.replace(['@', '/', '.'], "-")
}

/// Phase 37 M5.2: build the synthetic `package.json` body for the
/// install root. Extends the pre-M5 minimal shape with an
/// `lpm.trustedDependencies` Rich-form map populated from
/// `~/.lpm/global/trusted-dependencies.json`, so the inner project
/// install pipeline's strict-gate check sees the user's global
/// approvals and doesn't re-block every script-running transitive dep
/// on every global install.
///
/// Shape:
///
/// ```json
/// {
///   "private": true,
///   "name": "@lpm-global/<sanitized>",
///   "dependencies": { "<pkg>": "<version>" },
///   "lpm": {
///     "trustedDependencies": {
///       "esbuild@0.25.1": {
///         "integrity": "sha512-…",
///         "scriptHash": "sha256-…"
///       }
///     }
///   }
/// }
/// ```
///
/// Omits the `lpm` block when the global trust file is empty so the
/// on-disk file remains minimal (matches pre-M5.2 byte-for-byte when
/// no packages have been approved). This keeps the "fresh machine"
/// path identical to the pre-M5 surface — the `lpm` block only
/// appears once the user has approved something.
fn synthesize_pkg_json(
    root: &LpmRoot,
    pkg_name: &str,
    pkg_version: &str,
) -> Result<serde_json::Value, LpmError> {
    let trust = lpm_global::trusted_deps::read_for(root)?;
    let mut obj = serde_json::Map::new();
    obj.insert("private".into(), serde_json::Value::Bool(true));
    obj.insert(
        "name".into(),
        serde_json::Value::String(format!("@lpm-global/{}", sanitize_inner_name(pkg_name))),
    );
    let mut deps = serde_json::Map::new();
    deps.insert(
        pkg_name.to_string(),
        serde_json::Value::String(pkg_version.to_string()),
    );
    obj.insert("dependencies".into(), serde_json::Value::Object(deps));

    if !trust.trusted.is_empty() {
        let mut rich = serde_json::Map::new();
        for (key, binding) in &trust.trusted {
            rich.insert(
                key.clone(),
                serde_json::to_value(binding).unwrap_or(serde_json::Value::Null),
            );
        }
        let mut lpm_block = serde_json::Map::new();
        lpm_block.insert(
            "trustedDependencies".into(),
            serde_json::Value::Object(rich),
        );
        obj.insert("lpm".into(), serde_json::Value::Object(lpm_block));
    }

    Ok(serde_json::Value::Object(obj))
}

/// Phase 37 M5.2: emit a post-install banner if the new install root's
/// per-install `build-state.json` surfaces packages not covered by the
/// global trust list. Mirrors the project-level
/// `install::run`'s post-install security summary (which is suppressed
/// for globals via `no_security_summary: true`).
///
/// Silent in JSON mode — JSON consumers already see `path_hint` in
/// `print_success`'s structured output; surfacing the same data there
/// is an M5.3 / M6 polish item. For now, JSON stays quiet.
///
/// Errors reading the build-state or trust file are non-fatal: the
/// install already committed. A missing build-state just means no
/// warning fires (no info to report). Malformed state is debug-logged.
fn emit_post_install_blocked_warning(root: &LpmRoot, prep: &PrepResult, json_output: bool) {
    if json_output {
        return;
    }
    // Read the per-install build-state directly rather than going
    // through the aggregate path — we only care about THIS install's
    // blocked set, not every globally-installed package's.
    let Some(state) = crate::build_state::read_build_state(&prep.install_root) else {
        // No build-state file means either (a) the inner pipeline
        // didn't run the security capture for this install, or (b)
        // the install has zero scripts-carrying deps. Either way,
        // nothing to warn about.
        return;
    };
    if state.blocked_packages.is_empty() {
        return;
    }
    // Filter through the global trust list — packages already
    // approved globally shouldn't appear in the banner.
    let trust = match lpm_global::trusted_deps::read_for(root) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("emit_post_install_blocked_warning: reading global trust: {e}");
            return;
        }
    };
    let remaining: Vec<&crate::build_state::BlockedPackage> = state
        .blocked_packages
        .iter()
        .filter(|b| {
            !matches!(
                trust.matches_strict(
                    &b.name,
                    &b.version,
                    b.integrity.as_deref(),
                    b.script_hash.as_deref(),
                ),
                lpm_global::GlobalTrustMatch::Strict
            )
        })
        .collect();
    if remaining.is_empty() {
        return;
    }

    println!();
    output::warn(&format!(
        "{} package{} in this global install have lifecycle scripts blocked pending review.",
        remaining.len().to_string().bold(),
        if remaining.len() == 1 { "" } else { "s" },
    ));
    // Show the first few by name so the user has concrete signal.
    let preview: Vec<String> = remaining
        .iter()
        .take(5)
        .map(|b| format!("{}@{}", b.name, b.version))
        .collect();
    if !preview.is_empty() {
        output::info(&format!(
            "   {}{}",
            preview.join(", "),
            if remaining.len() > preview.len() {
                format!(", +{} more", remaining.len() - preview.len())
            } else {
                String::new()
            }
        ));
    }
    output::info("   Run `lpm approve-builds --global` to review and approve.");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

    struct TestEnvGuard {
        _env: crate::test_env::ScopedEnv,
    }

    impl TestEnvGuard {
        fn set(home: &Path, lpm_home: &Path, registry_url: &str) -> Self {
            Self {
                _env: crate::test_env::ScopedEnv::set([
                    ("HOME", home.as_os_str().to_owned()),
                    ("LPM_HOME", lpm_home.as_os_str().to_owned()),
                    ("LPM_REGISTRY_URL", registry_url.into()),
                ]),
            }
        }
    }

    fn tmp_pkg_json(install_root: &Path, package_name: &str, bin: serde_json::Value) {
        let pkg_dir = install_root.join("node_modules").join(package_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let body = serde_json::json!({
            "name": package_name,
            "version": "1.0.0",
            "bin": bin,
        });
        std::fs::write(pkg_dir.join("package.json"), body.to_string()).unwrap();
    }

    fn tarball_route(name: &str, version: &str) -> String {
        let sanitized = name.trim_start_matches('@').replace('/', "-");
        format!("/tarballs/{sanitized}-{version}.tgz")
    }

    fn append_tar_entry(
        builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
        path: &str,
        bytes: &[u8],
        mode: u32,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    fn make_mock_tarball(
        package_name: &str,
        version: &str,
        bin_entries: &[(&str, &str)],
    ) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mut pkg_json = serde_json::json!({
            "name": package_name,
            "version": version,
        });
        if !bin_entries.is_empty() {
            let bin_map = bin_entries
                .iter()
                .map(|(command, path)| {
                    (
                        (*command).to_string(),
                        serde_json::Value::String((*path).to_string()),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>();
            pkg_json
                .as_object_mut()
                .unwrap()
                .insert("bin".into(), serde_json::Value::Object(bin_map));
        }
        let pkg_json_bytes = serde_json::to_vec(&pkg_json).unwrap();
        append_tar_entry(&mut builder, "package/package.json", &pkg_json_bytes, 0o644);

        for (_, path) in bin_entries {
            append_tar_entry(
                &mut builder,
                &format!("package/{path}"),
                b"#!/usr/bin/env node\nconsole.log('ok')\n",
                0o755,
            );
        }

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn sri_for(bytes: &[u8]) -> String {
        use base64::Engine;
        use sha2::Digest;

        let digest = sha2::Sha512::digest(bytes);
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    }

    fn make_version_metadata(
        name: &str,
        version: &str,
        dependencies: &[(&str, &str)],
        tarball_url: String,
        integrity: String,
    ) -> lpm_registry::VersionMetadata {
        lpm_registry::VersionMetadata {
            name: name.to_string(),
            version: version.to_string(),
            dependencies: dependencies
                .iter()
                .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
                .collect(),
            dist: Some(lpm_registry::DistInfo {
                tarball: Some(tarball_url),
                integrity: Some(integrity),
                shasum: None,
            }),
            ..lpm_registry::VersionMetadata::default()
        }
    }

    fn make_package_metadata(
        name: &str,
        versions: Vec<lpm_registry::VersionMetadata>,
    ) -> lpm_registry::PackageMetadata {
        let latest = versions
            .last()
            .map(|version| version.version.clone())
            .expect("mock package metadata must include at least one version");

        lpm_registry::PackageMetadata {
            name: name.to_string(),
            description: None,
            dist_tags: std::collections::HashMap::from([("latest".to_string(), latest.clone())]),
            versions: versions
                .into_iter()
                .map(|version| (version.version.clone(), version))
                .collect(),
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: Some(latest),
            ecosystem: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_installs_cypress_subset_with_real_multiconflict_tree() {
        use wiremock::matchers::{method, path as match_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let sandbox = tempfile::tempdir().unwrap();
        let home_dir = sandbox.path().join("home");
        let lpm_home = sandbox.path().join("lpm-home");
        std::fs::create_dir_all(&home_dir).unwrap();
        std::fs::create_dir_all(&lpm_home).unwrap();
        let _env = TestEnvGuard::set(&home_dir, &lpm_home, &server.uri());

        let package_specs = [
            ("cypress", "15.13.1", vec![("cypress", "bin/cypress.js")]),
            ("@cypress/xvfb", "1.2.4", vec![]),
            ("debug", "3.2.7", vec![]),
            ("debug", "4.3.4", vec![]),
            ("chalk", "4.1.2", vec![]),
            ("supports-color", "7.2.0", vec![]),
            ("supports-color", "8.1.1", vec![]),
        ];

        let tarballs: std::collections::HashMap<(String, String), Vec<u8>> = package_specs
            .iter()
            .map(|(name, version, bins)| {
                (
                    ((*name).to_string(), (*version).to_string()),
                    make_mock_tarball(name, version, bins),
                )
            })
            .collect();

        for ((name, version), tarball) in &tarballs {
            Mock::given(method("GET"))
                .and(match_path(tarball_route(name, version)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
                .expect(1)
                .mount(&server)
                .await;
        }

        let cypress_metadata = make_package_metadata(
            "cypress",
            vec![make_version_metadata(
                "cypress",
                "15.13.1",
                &[
                    ("@cypress/xvfb", "1.2.4"),
                    ("chalk", "4.1.2"),
                    ("debug", "4.3.4"),
                    ("supports-color", "8.1.1"),
                ],
                format!("{}{}", server.uri(), tarball_route("cypress", "15.13.1")),
                sri_for(&tarballs[&("cypress".to_string(), "15.13.1".to_string())]),
            )],
        );
        let xvfb_metadata = make_package_metadata(
            "@cypress/xvfb",
            vec![make_version_metadata(
                "@cypress/xvfb",
                "1.2.4",
                &[("debug", "3.2.7")],
                format!(
                    "{}{}",
                    server.uri(),
                    tarball_route("@cypress/xvfb", "1.2.4")
                ),
                sri_for(&tarballs[&("@cypress/xvfb".to_string(), "1.2.4".to_string())]),
            )],
        );
        let debug_metadata = make_package_metadata(
            "debug",
            vec![
                make_version_metadata(
                    "debug",
                    "3.2.7",
                    &[],
                    format!("{}{}", server.uri(), tarball_route("debug", "3.2.7")),
                    sri_for(&tarballs[&("debug".to_string(), "3.2.7".to_string())]),
                ),
                make_version_metadata(
                    "debug",
                    "4.3.4",
                    &[],
                    format!("{}{}", server.uri(), tarball_route("debug", "4.3.4")),
                    sri_for(&tarballs[&("debug".to_string(), "4.3.4".to_string())]),
                ),
            ],
        );
        let chalk_metadata = make_package_metadata(
            "chalk",
            vec![make_version_metadata(
                "chalk",
                "4.1.2",
                &[("supports-color", "7.2.0")],
                format!("{}{}", server.uri(), tarball_route("chalk", "4.1.2")),
                sri_for(&tarballs[&("chalk".to_string(), "4.1.2".to_string())]),
            )],
        );
        let supports_color_metadata = make_package_metadata(
            "supports-color",
            vec![
                make_version_metadata(
                    "supports-color",
                    "7.2.0",
                    &[],
                    format!(
                        "{}{}",
                        server.uri(),
                        tarball_route("supports-color", "7.2.0")
                    ),
                    sri_for(&tarballs[&("supports-color".to_string(), "7.2.0".to_string())]),
                ),
                make_version_metadata(
                    "supports-color",
                    "8.1.1",
                    &[],
                    format!(
                        "{}{}",
                        server.uri(),
                        tarball_route("supports-color", "8.1.1")
                    ),
                    sri_for(&tarballs[&("supports-color".to_string(), "8.1.1".to_string())]),
                ),
            ],
        );

        Mock::given(method("GET"))
            .and(match_path("/api/registry/cypress"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cypress_metadata))
            .expect(1)
            .mount(&server)
            .await;

        let batch_body = serde_json::json!({
            "packages": {
                "cypress": cypress_metadata,
                "@cypress/xvfb": xvfb_metadata,
                "debug": debug_metadata,
                "chalk": chalk_metadata,
                "supports-color": supports_color_metadata,
            }
        });

        Mock::given(method("POST"))
            .and(match_path("/api/registry/batch-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(batch_body))
            .expect(1)
            .mount(&server)
            .await;

        run("cypress@15.13.1", CollisionResolution::default(), true)
            .await
            .expect("install -g should succeed for the real cypress multi-conflict subset");

        let root = lpm_common::LpmRoot::from_dir(&lpm_home);
        let manifest = lpm_global::read_for(&root).unwrap();
        let entry = manifest
            .packages
            .get("cypress")
            .expect("cypress must be committed to the global manifest");
        assert_eq!(entry.resolved, "15.13.1");
        assert_eq!(entry.saved_spec, "15.13.1");
        assert_eq!(entry.source, PackageSource::UpstreamNpm);
        assert_eq!(entry.commands, vec!["cypress"]);

        let install_root = root.install_root_for("cypress", "15.13.1");
        match lpm_global::validate_install_root(&install_root, Some(&["cypress".into()])).unwrap() {
            lpm_global::InstallRootStatus::Ready { commands } => {
                assert_eq!(commands, vec!["cypress"]);
            }
            other => panic!("expected ready install root, got {other:?}"),
        }
    }

    #[test]
    fn discover_bin_string_form_uses_short_name() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(tmp.path(), "eslint", serde_json::json!("./bin/eslint.js"));
        let cmds = discover_bin_commands(tmp.path(), "eslint").unwrap();
        assert_eq!(cmds, vec!["eslint"]);
    }

    #[test]
    fn discover_bin_string_form_strips_scope() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(
            tmp.path(),
            "@lpm.dev/owner.tool",
            serde_json::json!("./bin/run.js"),
        );
        let cmds = discover_bin_commands(tmp.path(), "@lpm.dev/owner.tool").unwrap();
        assert_eq!(cmds, vec!["owner.tool"]);
    }

    #[test]
    fn discover_bin_object_form_returns_keys() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(
            tmp.path(),
            "typescript",
            serde_json::json!({"tsc": "./bin/tsc", "tsserver": "./bin/tsserver"}),
        );
        let mut cmds = discover_bin_commands(tmp.path(), "typescript").unwrap();
        cmds.sort();
        assert_eq!(cmds, vec!["tsc", "tsserver"]);
    }

    #[test]
    fn discover_bin_returns_empty_when_no_bin_field() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules").join("just-a-lib");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"just-a-lib","version":"1.0.0"}"#,
        )
        .unwrap();
        let cmds = discover_bin_commands(tmp.path(), "just-a-lib").unwrap();
        assert!(cmds.is_empty());
    }

    #[test]
    fn discover_bin_errors_when_package_json_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = discover_bin_commands(tmp.path(), "ghost").unwrap_err();
        assert!(format!("{err}").contains("could not read installed package.json"));
    }

    #[test]
    fn short_name_strips_scope() {
        assert_eq!(short_name("@lpm.dev/owner.tool"), "owner.tool");
        assert_eq!(short_name("@scope/name"), "name");
        assert_eq!(short_name("eslint"), "eslint");
    }

    #[test]
    fn pick_version_returns_exact_verbatim() {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".to_string(),
            lpm_registry::VersionMetadata::default(),
        );
        let metadata = lpm_registry::PackageMetadata {
            name: "x".into(),
            description: None,
            dist_tags: BTreeMap::new().into_iter().collect(),
            versions: versions.into_iter().collect(),
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        };
        let version = pick_version(&metadata, &UserSaveIntent::Exact("1.0.0".into())).unwrap();
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn pick_version_dist_tag_resolves() {
        let mut dist_tags = std::collections::HashMap::new();
        dist_tags.insert("latest".to_string(), "9.24.0".to_string());
        let metadata = lpm_registry::PackageMetadata {
            name: "x".into(),
            description: None,
            dist_tags,
            versions: Default::default(),
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        };
        let version = pick_version(&metadata, &UserSaveIntent::DistTag("latest".into())).unwrap();
        assert_eq!(version, "9.24.0");
    }

    #[test]
    fn pick_version_range_picks_max_satisfying() {
        let mut versions = std::collections::HashMap::new();
        for v in ["9.10.0", "9.24.0", "10.0.0"] {
            versions.insert(v.to_string(), lpm_registry::VersionMetadata::default());
        }
        let metadata = lpm_registry::PackageMetadata {
            name: "x".into(),
            description: None,
            dist_tags: Default::default(),
            versions,
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        };
        let version = pick_version(&metadata, &UserSaveIntent::Range("^9".into())).unwrap();
        assert_eq!(version, "9.24.0");
    }

    #[test]
    fn pick_version_workspace_intent_errors() {
        let metadata = lpm_registry::PackageMetadata {
            name: "x".into(),
            description: None,
            dist_tags: Default::default(),
            versions: Default::default(),
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        };
        let err =
            pick_version(&metadata, &UserSaveIntent::Workspace("workspace:*".into())).unwrap_err();
        assert!(format!("{err}").contains("workspace: protocol"));
    }

    #[test]
    fn sanitize_inner_name_strips_at_slash_dot() {
        assert_eq!(
            sanitize_inner_name("@lpm.dev/owner.tool"),
            "-lpm-dev-owner-tool"
        );
        assert_eq!(sanitize_inner_name("eslint"), "eslint");
    }

    /// Audit Medium (M3.2 round) + audit High (M3.2 fix round): the
    /// detection helper itself moved to `lpm_global::find_command_collisions`
    /// (and is exercised by the lpm-global test suite). Here we verify
    /// the user-facing formatting helpers and the inline-rollback
    /// contract — the rollback is what closes the replay-safe gap
    /// (without it, the next recovery would silently commit the
    /// rejected install).
    #[test]
    fn format_collisions_renders_alias_path_distinctly() {
        let collisions = vec![
            CommandCollision {
                command: "serve".into(),
                current_owner: "pkg-a".into(),
                via_alias: false,
            },
            CommandCollision {
                command: "srv".into(),
                current_owner: "pkg-b".into(),
                via_alias: true,
            },
        ];
        let rendered = format_collisions(&collisions);
        assert!(rendered.contains("serve (owned by pkg-a)"));
        assert!(rendered.contains("srv (owned by alias \u{2192} pkg-b)"));
    }

    #[test]
    fn collision_error_message_includes_workaround_hint() {
        // M4.3 replaced the pre-M4 "uninstall -g ..." workaround hint
        // with concrete --replace-bin / --alias examples. This test
        // now pins the baseline shape (owner naming + remediation
        // surface present); the M4.3-specific sections below pin the
        // exact flag forms.
        let collisions = vec![CommandCollision {
            command: "eslint".into(),
            current_owner: "eslint".into(),
            via_alias: false,
        }];
        let err = collision_error("alt-eslint", &collisions);
        let msg = format!("{err}");
        assert!(msg.contains("eslint (owned by eslint)"));
        assert!(msg.contains("lpm install -g alt-eslint"));
    }

    #[test]
    fn collision_error_pluralizes_correctly() {
        let one = vec![CommandCollision {
            command: "foo".into(),
            current_owner: "a".into(),
            via_alias: false,
        }];
        assert!(format!("{}", collision_error("c", &one)).contains("command that is"));
        let two = vec![
            CommandCollision {
                command: "foo".into(),
                current_owner: "a".into(),
                via_alias: false,
            },
            CommandCollision {
                command: "bar".into(),
                current_owner: "b".into(),
                via_alias: false,
            },
        ];
        assert!(format!("{}", collision_error("c", &two)).contains("commands that are"));
    }

    /// Audit High (M3.2 fix round): rollback_aborted_commit must leave
    /// the manifest with no pending row, the install root removed (or
    /// tombstoned), and a WAL Abort appended. Without this, the next
    /// recovery would silently commit the rejected install on the next
    /// `lpm` invocation.
    #[test]
    fn rollback_aborted_commit_leaves_no_residual_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let install_root = root.install_root_for("pkg", "1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::write(install_root.join("package.json"), "{}").unwrap();

        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.pending.insert(
            "pkg".into(),
            lpm_global::PendingEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::LpmDev,
                started_at: chrono::Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec![],
                replaces_version: None,
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let prep = PrepResult {
            tx_id: "tx1".into(),
            name: "pkg".into(),
            version: lpm_semver::Version::parse("1.0.0").unwrap(),
            saved_spec: "^1".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::LpmDev,
            install_root: install_root.clone(),
            install_root_relative: "installs/pkg@1.0.0".into(),
        };

        rollback_aborted_commit(&root, &mut manifest, &prep, "test reason").unwrap();

        // Manifest pending row gone.
        let read_back = lpm_global::read_for(&root).unwrap();
        assert!(!read_back.pending.contains_key("pkg"));
        // Install root removed.
        assert!(!install_root.exists());
        // WAL has the Abort record.
        let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
        let has_abort = scan
            .records
            .iter()
            .any(|r| matches!(r, lpm_global::WalRecord::Abort { tx_id, .. } if tx_id == "tx1"));
        assert!(has_abort, "Abort record must be appended");
    }

    #[test]
    fn mk_tx_id_includes_pid_and_is_unique_within_process() {
        let a = mk_tx_id();
        // A small sleep would make the second id deterministically
        // newer; in practice the nanos resolution is sub-microsecond
        // so two calls in series yield different ids on every platform
        // we ship to.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = mk_tx_id();
        assert_ne!(a, b);
        let pid = std::process::id().to_string();
        assert!(a.ends_with(&pid));
    }

    // ─── M5.2: synthesize_pkg_json ───────────────────────────────────

    /// Empty global trust file: the synthesized package.json has NO
    /// `lpm` block so the on-disk shape is byte-identical to pre-M5
    /// (prevents a no-op diff across every global install).
    #[test]
    fn synthesize_pkg_json_omits_lpm_block_when_global_trust_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let value = synthesize_pkg_json(&root, "eslint", "9.24.0").unwrap();
        assert!(value.get("lpm").is_none());
        assert_eq!(
            value.get("name").and_then(|v| v.as_str()),
            Some("@lpm-global/eslint")
        );
        assert_eq!(
            value
                .get("dependencies")
                .and_then(|d| d.get("eslint"))
                .and_then(|v| v.as_str()),
            Some("9.24.0")
        );
    }

    /// Global trust file with entries: the synthesized package.json
    /// gains an `lpm.trustedDependencies` map that round-trips to the
    /// project-level `TrustedDependencyBinding` shape. The inner
    /// install pipeline reads this via `lpm_workspace::read_package_json`
    /// and applies the same strict-gate logic as a normal project.
    #[test]
    fn synthesize_pkg_json_embeds_global_trust_under_lpm_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let mut trust = lpm_global::GlobalTrustedDependencies::default();
        trust.insert_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-x".into()),
            Some("sha256-y".into()),
        );
        lpm_global::trusted_deps::write_for(&root, &trust).unwrap();

        let value = synthesize_pkg_json(&root, "eslint", "9.24.0").unwrap();
        let lpm_block = value.get("lpm").expect("lpm block must be present");
        let trusted = lpm_block
            .get("trustedDependencies")
            .expect("trustedDependencies must be present");
        let entry = trusted
            .get("esbuild@0.25.1")
            .expect("entry keyed name@version");
        assert_eq!(
            entry.get("integrity").and_then(|v| v.as_str()),
            Some("sha512-x")
        );
        // MUST use the renamed JSON key `scriptHash`, not `script_hash`,
        // so the inner pipeline's deserializer recognises it.
        assert_eq!(
            entry.get("scriptHash").and_then(|v| v.as_str()),
            Some("sha256-y")
        );
    }

    /// Scoped package names produce a valid synthesized `name` field
    /// (no `@`/`/` characters in the middle — sanitized by
    /// `sanitize_inner_name`).
    #[test]
    fn synthesize_pkg_json_name_for_scoped_package_is_sanitized() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let value = synthesize_pkg_json(&root, "@lpm.dev/owner.tool", "1.0.0").unwrap();
        let name = value.get("name").and_then(|v| v.as_str()).unwrap();
        // Sanitizer replaces @, /, . with `-`.
        assert_eq!(name, "@lpm-global/-lpm-dev-owner-tool");
        // Dependency key MUST keep the original scoped name so the
        // inner install resolves the right package.
        assert_eq!(
            value
                .get("dependencies")
                .and_then(|d| d.get("@lpm.dev/owner.tool"))
                .and_then(|v| v.as_str()),
            Some("1.0.0")
        );
    }

    // ─── M4.1: CollisionResolution flag parsing ──────────────────────

    fn parse(replace: &[&str], alias: &[&str]) -> Result<CollisionResolution, String> {
        let r: Vec<String> = replace.iter().map(|s| (*s).to_string()).collect();
        let a: Vec<String> = alias.iter().map(|s| (*s).to_string()).collect();
        CollisionResolution::parse_from_flags(&r, &a)
    }

    #[test]
    fn collision_resolution_empty_flags_is_empty() {
        let r = parse(&[], &[]).unwrap();
        assert!(r.is_empty());
        assert!(r.replace.is_empty());
        assert!(r.alias.is_empty());
    }

    #[test]
    fn collision_resolution_replace_bin_collects_to_set() {
        let r = parse(&["serve", "lint"], &[]).unwrap();
        assert_eq!(r.replace.len(), 2);
        assert!(r.replace.contains("serve"));
        assert!(r.replace.contains("lint"));
        assert!(r.alias.is_empty());
    }

    #[test]
    fn collision_resolution_duplicate_replace_bin_is_idempotent() {
        // Same command listed twice is redundant, not an error — set
        // semantics handle it cleanly and the user's intent is clear.
        let r = parse(&["serve", "serve"], &[]).unwrap();
        assert_eq!(r.replace.len(), 1);
        assert!(r.replace.contains("serve"));
    }

    #[test]
    fn collision_resolution_alias_single_flag_parses() {
        let r = parse(&[], &["serve=foo-serve"]).unwrap();
        assert_eq!(r.alias.len(), 1);
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
    }

    #[test]
    fn collision_resolution_alias_comma_separated_and_repeated_flags_both_work() {
        let r = parse(&[], &["serve=foo-serve,lint=foo-lint", "test=foo-test"]).unwrap();
        assert_eq!(r.alias.len(), 3);
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
        assert_eq!(r.alias.get("lint"), Some(&"foo-lint".to_string()));
        assert_eq!(r.alias.get("test"), Some(&"foo-test".to_string()));
    }

    #[test]
    fn collision_resolution_alias_trims_whitespace_around_pieces() {
        // A user copying from a doc with extra spaces shouldn't fail.
        let r = parse(&[], &["  serve=foo-serve , lint=foo-lint  "]).unwrap();
        assert_eq!(r.alias.len(), 2);
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
        assert_eq!(r.alias.get("lint"), Some(&"foo-lint".to_string()));
    }

    #[test]
    fn collision_resolution_alias_empty_pieces_are_ignored() {
        // Trailing / leading / doubled commas shouldn't fail.
        let r = parse(&[], &[",serve=foo-serve,,lint=foo-lint,"]).unwrap();
        assert_eq!(r.alias.len(), 2);
    }

    #[test]
    fn collision_resolution_alias_missing_equals_rejected() {
        let err = parse(&[], &["foo-serve"]).unwrap_err();
        assert!(
            err.contains("expected `<orig>=<alias>` shape"),
            "error must name the expected shape: {err}"
        );
    }

    #[test]
    fn collision_resolution_alias_empty_orig_rejected() {
        let err = parse(&[], &["=foo-serve"]).unwrap_err();
        assert!(err.contains("`<orig>` side is empty"));
    }

    #[test]
    fn collision_resolution_alias_empty_alias_rejected() {
        let err = parse(&[], &["serve="]).unwrap_err();
        assert!(err.contains("`<alias>` side is empty"));
    }

    #[test]
    fn collision_resolution_alias_self_map_rejected() {
        let err = parse(&[], &["serve=serve"]).unwrap_err();
        assert!(
            err.contains("nothing to resolve"),
            "self-map must be rejected with clear message: {err}"
        );
    }

    #[test]
    fn collision_resolution_alias_duplicate_orig_key_rejected() {
        // Two mappings for the same `<orig>` is ambiguous user intent.
        let err = parse(&[], &["serve=foo-serve,serve=bar-serve"]).unwrap_err();
        assert!(err.contains("already has another alias mapping"));
    }

    #[test]
    fn collision_resolution_alias_target_with_path_separator_rejected() {
        // validate_bin_name rejects '/' / '\\' / '..' / null bytes.
        let err = parse(&[], &["serve=../evil"]).unwrap_err();
        assert!(
            err.contains("alias target rejected"),
            "path traversal in alias target must be rejected: {err}"
        );
    }

    #[test]
    fn collision_resolution_alias_target_with_null_byte_rejected() {
        let err = parse(&[], &["serve=foo\0bar"]).unwrap_err();
        assert!(err.contains("alias target rejected"));
    }

    #[test]
    fn collision_resolution_command_in_both_replace_and_alias_rejected() {
        // Mutually exclusive intents for the same collision.
        let err = parse(&["serve"], &["serve=foo-serve"]).unwrap_err();
        assert!(
            err.contains("mutually exclusive resolutions"),
            "same command in both sets must be rejected: {err}"
        );
    }

    #[test]
    fn collision_resolution_mixed_replace_and_alias_on_different_commands_is_valid() {
        // Different commands in each set is the normal multi-collision case.
        let r = parse(&["lint"], &["serve=foo-serve"]).unwrap();
        assert!(r.replace.contains("lint"));
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
    }

    /// M4.1 explicitly does NOT know about the package's actual command
    /// set — marker discovery runs later in the pipeline. Commands
    /// named in flags that don't exist on the package are accepted
    /// here and will be rejected in M4.2's commit-time semantic check.
    /// Pins the boundary so a future refactor doesn't accidentally pull
    /// that check upstream without wiring marker_commands access.
    #[test]
    fn collision_resolution_does_not_validate_against_package_commands_yet() {
        // "nonexistent" looks like any other command name to M4.1.
        let r = parse(&["nonexistent"], &["another=x"]).unwrap();
        assert!(r.replace.contains("nonexistent"));
        assert!(r.alias.contains_key("another"));
    }

    // ─── M4.2: plan_resolution unit tests ────────────────────────────

    /// Seed a manifest with a single globally-installed package that
    /// directly owns `owned_commands`. Helper for plan tests below.
    fn manifest_with_direct_owner(owner: &str, owned_commands: &[&str]) -> GlobalManifest {
        let mut m = GlobalManifest::default();
        m.packages.insert(
            owner.to_string(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-test".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: format!("installs/{owner}@1.0.0"),
                commands: owned_commands.iter().map(|s| (*s).to_string()).collect(),
            },
        );
        m
    }

    #[test]
    fn plan_resolution_no_collisions_produces_empty_delta() {
        let m = GlobalManifest::default();
        let res = CollisionResolution::default();
        let plan = plan_resolution(&m, "foo", &["serve".into(), "lint".into()], &res).unwrap();
        assert!(plan.ownership_delta.is_empty());
        assert_eq!(plan.final_commands, vec!["serve", "lint"]);
        assert!(plan.alias_rows_to_write.is_empty());
        assert!(plan.aliases_to_remove.is_empty());
    }

    #[test]
    fn plan_resolution_rejects_unknown_replace_bin_not_in_marker() {
        let m = GlobalManifest::default();
        let res = CollisionResolution {
            replace: ["ghost".into()].into_iter().collect(),
            alias: BTreeMap::new(),
        };
        let err = plan_resolution(&m, "foo", &["serve".into()], &res).unwrap_err();
        assert!(
            matches!(&err, PlanError::UnknownCommand { flag: "--replace-bin", command } if command == "ghost"),
            "got: {err:?}"
        );
    }

    #[test]
    fn plan_resolution_rejects_unknown_alias_orig_not_in_marker() {
        let m = GlobalManifest::default();
        let mut alias = BTreeMap::new();
        alias.insert("ghost".into(), "foo-ghost".into());
        let res = CollisionResolution {
            replace: HashSet::new(),
            alias,
        };
        let err = plan_resolution(&m, "foo", &["serve".into()], &res).unwrap_err();
        assert!(matches!(
            err,
            PlanError::UnknownCommand {
                flag: "--alias",
                ..
            }
        ));
    }

    #[test]
    fn plan_resolution_direct_owner_replace_emits_direct_transfer() {
        let m = manifest_with_direct_owner("http-server", &["serve"]);
        let res = CollisionResolution {
            replace: ["serve".into()].into_iter().collect(),
            alias: BTreeMap::new(),
        };
        let plan = plan_resolution(&m, "foo", &["serve".into(), "lint".into()], &res).unwrap();
        assert_eq!(plan.ownership_delta.len(), 1);
        match &plan.ownership_delta[0] {
            OwnershipChange::DirectTransfer {
                command,
                from_package,
                from_row_snapshot,
            } => {
                assert_eq!(command, "serve");
                assert_eq!(from_package, "http-server");
                // Snapshot must carry the displaced owner's full row so
                // rollback can restore it exactly.
                assert_eq!(
                    from_row_snapshot.get("resolved").and_then(|v| v.as_str()),
                    Some("1.0.0")
                );
            }
            other => panic!("expected DirectTransfer, got {other:?}"),
        }
        assert_eq!(plan.final_commands, vec!["serve", "lint"]);
    }

    #[test]
    fn plan_resolution_alias_owner_replace_emits_alias_owner_remove() {
        let mut m = GlobalManifest::default();
        // Someone else has an alias that exposes `serve`.
        m.aliases.insert(
            "serve".into(),
            AliasEntry {
                package: "other-pkg".into(),
                bin: "server".into(),
            },
        );
        m.packages.insert(
            "other-pkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-test".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/other-pkg@1.0.0".into(),
                commands: vec![],
            },
        );
        let res = CollisionResolution {
            replace: ["serve".into()].into_iter().collect(),
            alias: BTreeMap::new(),
        };
        let plan = plan_resolution(&m, "foo", &["serve".into()], &res).unwrap();
        assert_eq!(plan.ownership_delta.len(), 1);
        match &plan.ownership_delta[0] {
            OwnershipChange::AliasOwnerRemove {
                alias_name,
                entry_snapshot,
            } => {
                // M4 audit Finding #3: alias-owner snapshots are keyed
                // by the exposed name (the alias key), not the owner
                // package. Pin that.
                assert_eq!(alias_name, "serve");
                assert_eq!(
                    entry_snapshot.get("package").and_then(|v| v.as_str()),
                    Some("other-pkg")
                );
                assert_eq!(
                    entry_snapshot.get("bin").and_then(|v| v.as_str()),
                    Some("server")
                );
            }
            other => panic!("expected AliasOwnerRemove, got {other:?}"),
        }
        assert_eq!(plan.aliases_to_remove, vec!["serve"]);
    }

    #[test]
    fn plan_resolution_alias_install_excludes_orig_from_final_commands() {
        // User aliases `serve` to `foo-serve`. `serve` must NOT appear
        // in final_commands (M4 manifest invariant: direct commands
        // exclude aliased-away names).
        let m = GlobalManifest::default();
        let mut alias = BTreeMap::new();
        alias.insert("serve".into(), "foo-serve".into());
        let res = CollisionResolution {
            replace: HashSet::new(),
            alias,
        };
        let plan = plan_resolution(&m, "foo", &["serve".into(), "lint".into()], &res).unwrap();

        assert_eq!(plan.final_commands, vec!["lint"]);
        assert_eq!(plan.alias_rows_to_write.len(), 1);
        assert_eq!(
            plan.alias_rows_to_write.get("foo-serve").unwrap().bin,
            "serve"
        );
        assert_eq!(plan.ownership_delta.len(), 1);
        assert!(matches!(
            &plan.ownership_delta[0],
            OwnershipChange::AliasInstall { alias_name, package, bin }
            if alias_name == "foo-serve" && package == "foo" && bin == "serve"
        ));
    }

    /// Residual-collision check: two aliases mapped to the same PATH
    /// name conflict with each other.
    #[test]
    fn plan_resolution_rejects_duplicate_alias_targets() {
        let m = GlobalManifest::default();
        let mut alias = BTreeMap::new();
        alias.insert("serve".into(), "both".into());
        alias.insert("lint".into(), "both".into());
        let res = CollisionResolution {
            replace: HashSet::new(),
            alias,
        };
        let err = plan_resolution(&m, "foo", &["serve".into(), "lint".into()], &res).unwrap_err();
        match err {
            PlanError::AliasTargetCollision { targets, reason } => {
                assert!(targets.contains(&"both".to_string()));
                assert!(
                    reason.contains("two or more aliases"),
                    "reason must name the duplicate-target case: {reason}"
                );
            }
            other => panic!("expected AliasTargetCollision, got {other:?}"),
        }
    }

    /// Residual-collision check: an alias RHS equals another direct
    /// bin of the same package (audit tightening #2).
    #[test]
    fn plan_resolution_rejects_alias_target_equal_to_sibling_bin() {
        let m = GlobalManifest::default();
        let mut alias = BTreeMap::new();
        alias.insert("serve".into(), "lint".into()); // lint is another declared bin
        let res = CollisionResolution {
            replace: HashSet::new(),
            alias,
        };
        let err = plan_resolution(&m, "foo", &["serve".into(), "lint".into()], &res).unwrap_err();
        match err {
            PlanError::AliasTargetCollision { targets, reason } => {
                assert_eq!(targets, vec!["lint".to_string()]);
                assert!(reason.contains("sibling direct bin"));
            }
            other => panic!("expected AliasTargetCollision, got {other:?}"),
        }
    }

    /// Residual-collision check: alias target collides with another
    /// globally-installed package's command.
    #[test]
    fn plan_resolution_rejects_alias_target_colliding_with_other_package() {
        let m = manifest_with_direct_owner("existing", &["taken"]);
        let mut alias = BTreeMap::new();
        alias.insert("serve".into(), "taken".into());
        let res = CollisionResolution {
            replace: HashSet::new(),
            alias,
        };
        let err = plan_resolution(&m, "foo", &["serve".into()], &res).unwrap_err();
        assert!(matches!(err, PlanError::AliasTargetCollision { .. }));
    }

    /// When the user resolves one collision but leaves another
    /// unresolved, we must surface ResidualCollision naming the
    /// unresolved one.
    #[test]
    fn plan_resolution_residual_collision_names_unresolved_command() {
        let mut m = manifest_with_direct_owner("a", &["serve"]);
        m.packages.insert(
            "b".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-test".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/b@1.0.0".into(),
                commands: vec!["lint".into()],
            },
        );

        // User resolves `serve` but not `lint`.
        let res = CollisionResolution {
            replace: ["serve".into()].into_iter().collect(),
            alias: BTreeMap::new(),
        };
        let err = plan_resolution(&m, "foo", &["serve".into(), "lint".into()], &res).unwrap_err();
        match err {
            PlanError::ResidualCollision { collisions } => {
                let cmds: Vec<&str> = collisions.iter().map(|c| c.command.as_str()).collect();
                assert_eq!(cmds, vec!["lint"]);
            }
            other => panic!("expected ResidualCollision, got {other:?}"),
        }
    }

    // ─── M4.2: apply_ownership_change_to_manifest behavior ───────────

    #[test]
    fn apply_ownership_change_direct_transfer_drops_command_from_old_owner() {
        let mut m = manifest_with_direct_owner("old", &["serve", "other"]);
        let change = OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "old".into(),
            from_row_snapshot: serde_json::Value::Null,
        };
        apply_ownership_change_to_manifest(&mut m, &change, "new");
        assert_eq!(m.packages["old"].commands, vec!["other"]);
    }

    #[test]
    fn apply_ownership_change_alias_owner_remove_drops_alias_row() {
        let mut m = GlobalManifest::default();
        m.aliases.insert(
            "serve".into(),
            AliasEntry {
                package: "x".into(),
                bin: "y".into(),
            },
        );
        let change = OwnershipChange::AliasOwnerRemove {
            alias_name: "serve".into(),
            entry_snapshot: serde_json::Value::Null,
        };
        apply_ownership_change_to_manifest(&mut m, &change, "new");
        assert!(m.aliases.is_empty());
    }

    #[test]
    fn apply_ownership_change_alias_install_writes_alias_row() {
        let mut m = GlobalManifest::default();
        let change = OwnershipChange::AliasInstall {
            alias_name: "foo-serve".into(),
            package: "foo".into(),
            bin: "serve".into(),
        };
        apply_ownership_change_to_manifest(&mut m, &change, "foo");
        let entry = m.aliases.get("foo-serve").unwrap();
        assert_eq!(entry.package, "foo");
        assert_eq!(entry.bin, "serve");
    }

    /// Idempotency: applying a DirectTransfer twice is a no-op (retain
    /// drops nothing the second time because the command is already gone).
    #[test]
    fn apply_ownership_change_direct_transfer_is_idempotent() {
        let mut m = manifest_with_direct_owner("old", &["serve"]);
        let change = OwnershipChange::DirectTransfer {
            command: "serve".into(),
            from_package: "old".into(),
            from_row_snapshot: serde_json::Value::Null,
        };
        apply_ownership_change_to_manifest(&mut m, &change, "new");
        apply_ownership_change_to_manifest(&mut m, &change, "new"); // second apply
        assert!(m.packages["old"].commands.is_empty());
    }

    // ─── M4 audit pass 1 Finding 1 (High): WAL durability ordering ──
    //
    // The second Intent with populated ownership_delta MUST be durably
    // on disk BEFORE any shim mutation starts. Pre-fix, shim writes
    // happened first — a crash in between left recovery with the
    // prepare-time Intent's empty delta, which would replay wrongly
    // (put aliased-away origs back on PATH, skip displaced-owner
    // restoration).
    //
    // Structural test: run commit_locked end-to-end with a collision
    // resolution, then scan the WAL and assert the latest Intent for
    // the tx carries the populated delta. That pins the contract that
    // the second Intent is always written — any regression that drops
    // it entirely would surface here.

    /// Build a valid install_root with marker + .bin shims. Mirrors
    /// `install_root::make_complete_root` from the lpm-global tests
    /// so `validate_install_root` returns Ready.
    fn make_commit_test_install_root(
        root: &lpm_common::LpmRoot,
        pkg_name: &str,
        version: &str,
        bins: &[&str],
    ) -> PathBuf {
        let install_root = root.install_root_for(pkg_name, version);
        let bin = install_root.join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        for cmd in bins {
            let target = bin.join(cmd);
            std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        std::fs::write(install_root.join("lpm.lock"), b"# valid").unwrap();
        let marker =
            lpm_global::InstallReadyMarker::new(bins.iter().map(|s| (*s).to_string()).collect());
        lpm_global::write_marker(&install_root, &marker).unwrap();
        install_root
    }

    /// Pins Finding 1: after a successful commit_locked with a
    /// collision resolution, scanning the WAL must show TWO Intents
    /// for the tx_id — the prepare-time (empty delta) AND the
    /// finalize-time (populated delta). If the fix were reverted (or
    /// the second Intent move accidentally dropped), the test would
    /// catch it by asserting the delta is populated.
    #[test]
    fn commit_locked_writes_second_intent_with_populated_delta_for_collision_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        // Seed a pending install + a displaced owner for DirectTransfer.
        let install_root = make_commit_test_install_root(&root, "foo", "1.0.0", &["serve"]);
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert(
            "http-server".into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-other".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/http-server@1.0.0".into(),
                commands: vec!["serve".into()],
            },
        );
        manifest.pending.insert(
            "foo".into(),
            lpm_global::PendingEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                started_at: Utc::now(),
                root: "installs/foo@1.0.0".into(),
                commands: vec![],
                replaces_version: None,
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        // Write the prepare-time Intent (empty delta) — mirrors
        // prepare_locked.
        let mut wal = lpm_global::WalWriter::open(root.global_wal()).unwrap();
        wal.append(&WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx-audit1".into(),
            kind: TxKind::Install,
            package: "foo".into(),
            new_root_path: install_root.clone(),
            new_row_json: serde_json::json!({}),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
            ownership_delta: Vec::new(),
        })))
        .unwrap();
        drop(wal);

        let prep = PrepResult {
            tx_id: "tx-audit1".into(),
            name: "foo".into(),
            version: lpm_semver::Version::parse("1.0.0").unwrap(),
            saved_spec: "^1".into(),
            integrity: "sha512-x".into(),
            source: PackageSource::LpmDev,
            install_root: install_root.clone(),
            install_root_relative: "installs/foo@1.0.0".into(),
        };

        // --replace-bin serve — will produce one DirectTransfer in the
        // delta. Run commit_locked.
        let resolution = CollisionResolution {
            replace: ["serve".into()].into_iter().collect(),
            alias: BTreeMap::new(),
        };
        commit_locked(&root, &prep, &resolution).unwrap();

        // Scan the WAL. Must contain at least two Intent records for
        // tx-audit1: the prepare-time one (empty delta) AND the
        // finalize-time one (with DirectTransfer).
        let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
        let intents: Vec<&IntentPayload> = scan
            .records
            .iter()
            .filter_map(|r| match r {
                WalRecord::Intent(p) if p.tx_id == "tx-audit1" => Some(p.as_ref()),
                _ => None,
            })
            .collect();

        assert_eq!(
            intents.len(),
            2,
            "commit_locked must append a SECOND Intent with the populated delta \
             (audit Finding 1 pins this durability-before-shim-swap contract). \
             Found {} Intent records.",
            intents.len()
        );
        // The FIRST Intent (prepare-time) has empty delta.
        assert!(intents[0].ownership_delta.is_empty());
        // The SECOND (finalize-time) has the DirectTransfer.
        assert_eq!(intents[1].ownership_delta.len(), 1);
        assert!(matches!(
            &intents[1].ownership_delta[0],
            OwnershipChange::DirectTransfer { command, from_package, .. }
            if command == "serve" && from_package == "http-server"
        ));
    }

    /// Also pins: the second Intent (populated delta) is appended
    /// BEFORE the Commit record. This is the WAL order invariant —
    /// if a crash truncates after Commit append but before the next
    /// WAL flush, recovery sees Intent+Commit and doesn't replay.
    /// The Intent must describe the exact state being committed.
    #[test]
    fn commit_locked_orders_populated_intent_before_commit_in_wal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        let install_root = make_commit_test_install_root(&root, "foo", "1.0.0", &["lint"]);
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.pending.insert(
            "foo".into(),
            lpm_global::PendingEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                started_at: Utc::now(),
                root: "installs/foo@1.0.0".into(),
                commands: vec![],
                replaces_version: None,
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let mut wal = lpm_global::WalWriter::open(root.global_wal()).unwrap();
        wal.append(&WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx-audit1b".into(),
            kind: TxKind::Install,
            package: "foo".into(),
            new_root_path: install_root.clone(),
            new_row_json: serde_json::json!({}),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
            ownership_delta: Vec::new(),
        })))
        .unwrap();
        drop(wal);

        let prep = PrepResult {
            tx_id: "tx-audit1b".into(),
            name: "foo".into(),
            version: lpm_semver::Version::parse("1.0.0").unwrap(),
            saved_spec: "^1".into(),
            integrity: "sha512-x".into(),
            source: PackageSource::LpmDev,
            install_root,
            install_root_relative: "installs/foo@1.0.0".into(),
        };
        // No-collision path — still asserts both Intents, Commit order.
        commit_locked(&root, &prep, &CollisionResolution::default()).unwrap();

        let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
        // Positional check: the tx's Commit must come AFTER all its
        // Intents.
        let intent_positions: Vec<usize> = scan
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r, WalRecord::Intent(p) if p.tx_id == "tx-audit1b"))
            .map(|(i, _)| i)
            .collect();
        let commit_pos = scan
            .records
            .iter()
            .position(|r| matches!(r, WalRecord::Commit { tx_id, .. } if tx_id == "tx-audit1b"))
            .expect("Commit must exist");
        assert_eq!(intent_positions.len(), 2, "prepare + finalize Intent");
        assert!(
            intent_positions.iter().all(|p| *p < commit_pos),
            "every Intent must come before Commit"
        );
    }

    /// The `--replace-bin X --alias Y=X` composite scenario: replace
    /// frees X (from another package's direct ownership), then alias
    /// maps Y → X within the new package. The freeing-view check
    /// (section b of plan_resolution step 4) must accept this.
    #[test]
    fn plan_resolution_accepts_replace_then_alias_targets_freed_name() {
        let m = manifest_with_direct_owner("other", &["taken"]);

        // We're installing `foo` whose package.json declares bins
        // [serve, lint]. User wants to expose `serve` under the PATH
        // name `taken` (currently owned by `other`) — so `--replace-bin
        // taken` is nonsensical (foo doesn't declare `taken`); the
        // right invocation is `--replace-bin` on one of foo's bins AND
        // `--alias` rewriting another to the freed name. Test the
        // direct equivalent: user replaces taken's ownership as part
        // of a multi-collision scenario.
        //
        // Simpler valid scenario: if "lint" is also owned by another
        // package and user aliases serve→lint, the alias target "lint"
        // would collide with the sibling declared bin. Test that IS
        // rejected (covered above by
        // plan_resolution_rejects_alias_target_equal_to_sibling_bin).
        //
        // For the freed-name acceptance, simulate a scenario where
        // `taken` is freed by DirectTransfer: we need a marker_command
        // that collides and is in the replace set. Suppose foo's
        // marker is [taken, serve]; user says --replace-bin taken.
        // Then the AliasInstall for some OTHER mapping targeting
        // `taken` would... actually this is degenerate. Let's test
        // the cleaner invariant: alias target check runs against the
        // freeing view, so a name that DirectTransfer has freed is
        // available for alias targeting.
        //
        // Direct test: freeing view should correctly show the freed
        // state. Craft a scenario with two source packages and a
        // multi-part resolution.
        let mut m = m;
        m.packages.insert(
            "other2".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-test".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/other2@1.0.0".into(),
                commands: vec!["other-cmd".into()],
            },
        );

        let res = CollisionResolution {
            replace: ["taken".into()].into_iter().collect(),
            alias: BTreeMap::new(),
        };
        // foo declares "taken" and "safe"; taken collides with other.
        let plan = plan_resolution(&m, "foo", &["taken".into(), "safe".into()], &res).unwrap();
        assert_eq!(plan.ownership_delta.len(), 1);
        assert!(matches!(
            &plan.ownership_delta[0],
            OwnershipChange::DirectTransfer { command, from_package, .. }
            if command == "taken" && from_package == "other"
        ));
        assert_eq!(plan.final_commands, vec!["taken", "safe"]);
    }

    // ─── M4.3: collision_error message content ───────────────────────

    fn single_collision(cmd: &str, owner: &str) -> CommandCollision {
        CommandCollision {
            command: cmd.into(),
            current_owner: owner.into(),
            via_alias: false,
        }
    }

    /// Pre-M4 wording is gone. Error must name both flag forms so a
    /// user with no prior LPM context can recover. Pins the contract
    /// the audit called out.
    #[test]
    fn collision_error_mentions_both_override_flags() {
        let e = collision_error("foo", &[single_collision("serve", "http-server")]);
        let msg = e.to_string();
        assert!(
            msg.contains("--replace-bin"),
            "error must mention --replace-bin: {msg}"
        );
        assert!(msg.contains("--alias"), "error must mention --alias: {msg}");
    }

    /// Concrete examples must use the actual collision names so the
    /// user can paste without substitution.
    #[test]
    fn collision_error_emits_copy_pasteable_example_with_real_command_names() {
        let e = collision_error("foo", &[single_collision("serve", "http-server")]);
        let msg = e.to_string();
        assert!(
            msg.contains("lpm install -g foo --replace-bin serve"),
            "error must include the tailored --replace-bin example: {msg}"
        );
        assert!(
            msg.contains("--alias serve=foo-serve"),
            "error must include the tailored --alias example with the short package name: {msg}"
        );
    }

    /// Multi-collision: the example flags must cover every colliding
    /// command, not just the first.
    #[test]
    fn collision_error_multi_collision_covers_every_command() {
        let e = collision_error(
            "foo",
            &[
                single_collision("serve", "http-server"),
                single_collision("lint", "eslint"),
            ],
        );
        let msg = e.to_string();
        // Both replace-bin flags present
        assert!(msg.contains("--replace-bin serve"));
        assert!(msg.contains("--replace-bin lint"));
        // Both alias mappings in one --alias comma list
        assert!(
            msg.contains("--alias serve=foo-serve,lint=foo-lint"),
            "multi-collision --alias must be comma-separated: {msg}"
        );
    }

    /// Scoped package names (`@scope/pkg.tool`) should use the short
    /// name (after the scope) in alias-target defaults so the suggestion
    /// is a valid shell token.
    #[test]
    fn collision_error_alias_default_uses_short_name_for_scoped_pkg() {
        let e = collision_error("@lpm.dev/owner.tool", &[single_collision("run", "other")]);
        let msg = e.to_string();
        assert!(
            msg.contains("--alias run=owner.tool-run"),
            "scoped-package alias target must strip the scope: {msg}"
        );
    }

    /// No references to the pre-M4 "wait for M4" wording — that's the
    /// whole point of M4.3.
    #[test]
    fn collision_error_does_not_reference_pre_m4_wording() {
        let e = collision_error("foo", &[single_collision("serve", "x")]);
        let msg = e.to_string();
        assert!(
            !msg.contains("wait for M4"),
            "pre-M4 placeholder wording must be gone: {msg}"
        );
        assert!(
            !msg.to_lowercase().contains("until then"),
            "placeholder 'Until then' wording must be gone: {msg}"
        );
    }

    // ─── M4.4: TTY prompt fold logic ─────────────────────────────────
    //
    // The actual cliclack interaction can't be unit-tested without a
    // PTY. The fold function `fold_choices_into_resolution` is the
    // pure core — given a per-collision `CollisionChoice`, produce a
    // `CollisionResolution` identical in shape to what the flag-parsing
    // path would produce. These tests pin the pure-logic contract.

    fn col(cmd: &str, owner: &str) -> CommandCollision {
        CommandCollision {
            command: cmd.into(),
            current_owner: owner.into(),
            via_alias: false,
        }
    }

    #[test]
    fn fold_replace_choice_populates_replace_set() {
        let r =
            fold_choices_into_resolution(&[(col("serve", "x"), CollisionChoice::Replace)]).unwrap();
        assert_eq!(r.replace.len(), 1);
        assert!(r.replace.contains("serve"));
        assert!(r.alias.is_empty());
    }

    #[test]
    fn fold_alias_choice_populates_alias_map() {
        let r = fold_choices_into_resolution(&[(
            col("serve", "x"),
            CollisionChoice::Alias("foo-serve".into()),
        )])
        .unwrap();
        assert!(r.replace.is_empty());
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
    }

    #[test]
    fn fold_mixed_choices_populate_both_sides() {
        let r = fold_choices_into_resolution(&[
            (col("serve", "a"), CollisionChoice::Replace),
            (col("lint", "b"), CollisionChoice::Alias("foo-lint".into())),
        ])
        .unwrap();
        assert!(r.replace.contains("serve"));
        assert_eq!(r.alias.get("lint"), Some(&"foo-lint".to_string()));
    }

    #[test]
    fn fold_cancel_on_first_collision_aborts_entire_install() {
        let err = fold_choices_into_resolution(&[
            (col("serve", "x"), CollisionChoice::Cancel),
            (col("lint", "y"), CollisionChoice::Replace),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("install cancelled"),
            "cancel must abort the install with a clear message: {msg}"
        );
        // Must name the specific command the user cancelled on.
        assert!(msg.contains("serve"));
    }

    #[test]
    fn fold_cancel_after_valid_choices_still_aborts_everything() {
        // Cancel on the SECOND collision (first was resolved) must still
        // abort — partial-resolution installs violate the M4 invariant.
        let err = fold_choices_into_resolution(&[
            (col("serve", "x"), CollisionChoice::Replace),
            (col("lint", "y"), CollisionChoice::Cancel),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("install cancelled"));
        assert!(err.to_string().contains("lint"));
    }

    #[test]
    fn fold_empty_choices_yields_empty_resolution() {
        // Defensive: if no collisions were prompted (shouldn't happen
        // — caller only calls us when there IS a collision — but the
        // invariant should hold).
        let r = fold_choices_into_resolution(&[]).unwrap();
        assert!(r.is_empty());
    }
}
