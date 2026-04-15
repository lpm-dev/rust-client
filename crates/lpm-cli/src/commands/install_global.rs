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
    CommandCollision, InstallReadyMarker, InstallRootStatus, IntentPayload, PackageEntry,
    PackageSource, PendingEntry, Shim, TxKind, WalRecord, WalWriter, emit_shim,
    find_command_collisions, read_for, validate_install_root, write_for, write_marker,
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
    _resolution: CollisionResolution,
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
    do_install(&registry, &prep).await?;
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

    // ─── Step 3: validate + commit under .tx.lock ──────────────────
    let active = with_exclusive_lock(root.global_tx_lock(), || commit_locked(&root, &prep))?;

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

async fn do_install(registry: &RegistryClient, prep: &PrepResult) -> Result<(), LpmError> {
    // Mirror dlx's pattern: write a synthetic package.json with the
    // single dependency, then call the project install pipeline against
    // the install root. This reuses every byte of resolution / store /
    // linker logic — global install is a self-hosted install with a
    // specific synthetic project.
    std::fs::create_dir_all(&prep.install_root)?;
    let pkg_json = format!(
        r#"{{"private":true,"name":"@lpm-global/{}","dependencies":{{"{}":"{}"}}}}"#,
        sanitize_inner_name(&prep.name),
        prep.name,
        prep.version
    );
    std::fs::write(prep.install_root.join("package.json"), &pkg_json)?;

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
    let pkg_json_path = install_root
        .join("node_modules")
        .join(package_name)
        .join("package.json");
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

fn commit_locked(root: &LpmRoot, prep: &PrepResult) -> Result<CommitOutput, LpmError> {
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

    // Collision guard. Pre-fix this check returned `Err` and left the
    // pending row + install root + WAL Intent in place for recovery
    // to reconcile. But recovery's roll_forward did NOT run the same
    // check, so the next `lpm` invocation that triggered recovery
    // (any `global *`, `install -g`, `store gc/verify`, `cache clean`,
    // `doctor`) would silently commit the rejected install — audit
    // High from the M3.2 fix round.
    //
    // Now: detect collision, ROLL BACK INLINE (drop pending row,
    // tombstone install root, write WAL ABORT), then surface the
    // error. The state on disk is clean; recovery has nothing to do.
    let collisions = find_command_collisions(&manifest, &prep.name, &marker_commands);
    if !collisions.is_empty() {
        rollback_aborted_commit(root, &mut manifest, prep, &format_collisions(&collisions))?;
        return Err(collision_error(&prep.name, &collisions));
    }

    // Emit shims (commands only — aliases are M4).
    let bin_dir = root.bin_dir();
    let install_bin = prep.install_root.join("node_modules").join(".bin");
    for cmd in &marker_commands {
        let target = install_bin.join(cmd);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: cmd.clone(),
                target,
            },
        )?;
    }

    // Flip [pending] into [packages] with the marker's authoritative
    // commands.
    let active = PackageEntry {
        saved_spec: prep.saved_spec.clone(),
        resolved: prep.version.to_string(),
        integrity: prep.integrity.clone(),
        source: prep.source,
        installed_at: Utc::now(),
        root: prep.install_root_relative.clone(),
        commands: marker_commands.clone(),
    };
    manifest.packages.insert(prep.name.clone(), active);
    manifest.pending.remove(&prep.name);

    // Per-tx ordering invariant from the M3.1 audit: persist manifest
    // BEFORE WAL COMMIT. A crash between manifest persist and WAL
    // append is the "Already Committed" case recovery handles
    // explicitly.
    write_for(root, &manifest)?;

    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Commit {
        tx_id: prep.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(CommitOutput {
        name: prep.name.clone(),
        version: prep.version.to_string(),
        saved_spec: prep.saved_spec.clone(),
        source: prep.source,
        commands: marker_commands,
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

fn collision_error(installing_pkg: &str, collisions: &[CommandCollision]) -> LpmError {
    LpmError::Script(format!(
        "'{}' would expose command{} that {} already taken on this host:\n{}\n\nM4 will ship \
         interactive resolution + `--alias`/`--replace-bin` flags. Until then, \
         `lpm uninstall -g <existing-pkg>` first or pick a different package.",
        installing_pkg,
        if collisions.len() == 1 { "" } else { "s" },
        if collisions.len() == 1 { "is" } else { "are" },
        format_collisions(collisions)
    ))
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
    if prep.install_root.exists()
        && let Err(e) = std::fs::remove_dir_all(&prep.install_root)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

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
        let collisions = vec![CommandCollision {
            command: "eslint".into(),
            current_owner: "eslint".into(),
            via_alias: false,
        }];
        let err = collision_error("alt-eslint", &collisions);
        let msg = format!("{err}");
        assert!(msg.contains("eslint (owned by eslint)"));
        assert!(msg.contains("uninstall -g"));
        assert!(msg.contains("M4"));
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
}
