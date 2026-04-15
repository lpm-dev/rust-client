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
    InstallReadyMarker, InstallRootStatus, IntentPayload, PackageEntry, PackageSource,
    PendingEntry, Shim, TxKind, WalRecord, WalWriter, emit_shim, read_for, validate_install_root,
    write_for, write_marker,
};
use lpm_registry::RegistryClient;
use lpm_semver::{Version, VersionReq};
use owo_colors::OwoColorize;
use std::path::PathBuf;

pub async fn run(spec: &str, json_output: bool) -> Result<(), LpmError> {
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

    // ─── Output ────────────────────────────────────────────────────
    print_success(&active, json_output);
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

    // Collision guard.
    if let Some(err) = check_no_command_collisions(&manifest, &prep.name, &marker_commands) {
        return Err(err);
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

/// Pre-M4 collision guard. M4 will ship a proper resolution UX (alias
/// / replace prompts); until then we MUST refuse to silently overwrite
/// another package's shim. Without this guard, two packages exposing
/// the same command name would both claim it in the manifest while
/// only the later install's shim survives on PATH — silent state
/// corruption.
///
/// Returns `Some(err)` when one or more commands collide with a package
/// other than `installing_pkg` (in M3.2 the installing package's own
/// pending row carries `commands == []`, so it never contributes to
/// `exposed_commands()`; the guard against collisions with itself is
/// belt-and-braces for future M3.4 upgrade flows that may pre-resolve).
fn check_no_command_collisions(
    manifest: &lpm_global::GlobalManifest,
    installing_pkg: &str,
    marker_commands: &[String],
) -> Option<LpmError> {
    let exposed = manifest.exposed_commands();
    let conflicting: Vec<&String> = marker_commands
        .iter()
        .filter(|cmd| {
            // A command is a real conflict when it's already in
            // exposed_commands() AND its owner is some OTHER package.
            // Self-collisions (the installing package re-asserting its
            // own commands) are handled by the existing
            // packages-already-contains check in prepare_locked.
            if !exposed.contains(*cmd) {
                return false;
            }
            match manifest.owner_of_command(cmd) {
                Some(owner) => owner.package != installing_pkg,
                None => true,
            }
        })
        .collect();
    if conflicting.is_empty() {
        return None;
    }
    let mut details: Vec<String> = Vec::new();
    for cmd in &conflicting {
        if let Some(owner) = manifest.owner_of_command(cmd) {
            details.push(format!(
                "  {} (owned by {})",
                cmd,
                if owner.via_alias {
                    format!("alias \u{2192} {}", owner.package)
                } else {
                    owner.package.to_string()
                }
            ));
        } else {
            details.push(format!("  {cmd}"));
        }
    }
    Some(LpmError::Script(format!(
        "'{}' would expose command{} that {} already taken on this host:\n{}\n\nM4 will ship \
         interactive resolution + `--alias`/`--replace-bin` flags. Until then, \
         `lpm uninstall -g <existing-pkg>` first or pick a different package.",
        installing_pkg,
        if conflicting.len() == 1 { "" } else { "s" },
        if conflicting.len() == 1 { "is" } else { "are" },
        details.join("\n")
    )))
}

// ─── Output ──────────────────────────────────────────────────────────

fn print_success(out: &CommitOutput, json_output: bool) {
    if json_output {
        let body = serde_json::json!({
            "success": true,
            "package": out.name,
            "version": out.version,
            "saved_spec": out.saved_spec,
            "source": out.source,
            "commands": out.commands,
            "install_root": out.install_root.display().to_string(),
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

    fn manifest_with_package(name: &str, commands: &[&str]) -> lpm_global::GlobalManifest {
        let mut m = lpm_global::GlobalManifest::default();
        m.packages.insert(
            name.into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::LpmDev,
                installed_at: chrono::Utc::now(),
                root: format!("installs/{name}@1.0.0"),
                commands: commands.iter().map(|s| s.to_string()).collect(),
            },
        );
        m
    }

    /// Audit Medium (M3.2 round): commit must refuse to silently
    /// overwrite another package's shim. Pre-fix `emit_shim` would
    /// happily replace the existing shim and the manifest would end
    /// up with two rows claiming the same command.
    #[test]
    fn collision_check_errors_when_another_package_owns_the_command() {
        let manifest = manifest_with_package("eslint", &["eslint"]);
        let err = check_no_command_collisions(&manifest, "alt-eslint", &["eslint".to_string()])
            .expect("expected a collision error");
        let msg = format!("{err}");
        assert!(
            msg.contains("eslint (owned by eslint)"),
            "msg should name the conflicting owner, got: {msg}"
        );
        assert!(
            msg.contains("uninstall -g"),
            "msg should hint at the workaround"
        );
    }

    #[test]
    fn collision_check_passes_when_no_overlap() {
        let manifest = manifest_with_package("eslint", &["eslint"]);
        assert!(
            check_no_command_collisions(&manifest, "tsc-installer", &["tsc".to_string()]).is_none()
        );
    }

    #[test]
    fn collision_check_ignores_self_owned_commands() {
        // A package re-asserting its own commands isn't a collision
        // with itself. (M3.2 doesn't hit this because pending.commands
        // is [] and the installing package's row isn't in packages
        // yet, but M3.4 upgrades will and we want belt-and-braces.)
        let manifest = manifest_with_package("eslint", &["eslint"]);
        assert!(
            check_no_command_collisions(&manifest, "eslint", &["eslint".to_string()]).is_none()
        );
    }

    #[test]
    fn collision_check_detects_alias_collision() {
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.aliases.insert(
            "srv".into(),
            lpm_global::AliasEntry {
                package: "pkg-b".into(),
                bin: "serve".into(),
            },
        );
        let err = check_no_command_collisions(&manifest, "pkg-c", &["srv".to_string()])
            .expect("expected an alias collision");
        let msg = format!("{err}");
        assert!(
            msg.contains("alias"),
            "msg should mention the alias path: {msg}"
        );
    }

    #[test]
    fn collision_check_reports_all_conflicting_commands() {
        let mut manifest = manifest_with_package("a", &["foo", "shared"]);
        manifest.packages.insert(
            "b".into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-y".into(),
                source: lpm_global::PackageSource::LpmDev,
                installed_at: chrono::Utc::now(),
                root: "installs/b@1.0.0".into(),
                commands: vec!["bar".into()],
            },
        );
        let err = check_no_command_collisions(
            &manifest,
            "c",
            &["shared".to_string(), "bar".to_string(), "novel".to_string()],
        )
        .expect("two collisions expected");
        let msg = format!("{err}");
        assert!(msg.contains("shared"), "{msg}");
        assert!(msg.contains("bar"), "{msg}");
        assert!(
            !msg.contains("novel"),
            "{msg} should not flag non-conflicts"
        );
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
}
