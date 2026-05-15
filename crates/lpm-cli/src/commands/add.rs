use crate::output;
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{RegistryClient, RouteTable};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::prompt::prompt_err;

/// Result of handling a file conflict.
enum ConflictAction {
    Skip,
    Overwrite,
}

/// What `lpm add` resolved the user's input to.
///
/// Phase 60 (D-decoupling): `lpm add` is no longer LPM-only. The
/// `Lpm` variant flows through the lpm.dev metadata API and `PackageName`'s
/// strict `owner.name` validation. The `Npm` variant flows through the
/// npm metadata API (or `.npmrc`-declared registry per `RouteTable`)
/// and carries the original input string verbatim — bare names, scoped
/// names, anything npm accepts.
///
/// Encoding identity as an enum (rather than `Option<PackageName>` or a
/// runtime `is_lpm` check) means anywhere we hand `&PackageName` off to
/// a lpm.dev-only API (skills extraction, rich-config flow), the type
/// system proves we have one — and anywhere we render output for a non-
/// LPM target, the lpm.dev-prefixed `PackageName::scoped()` is statically
/// out of reach.
#[derive(Debug, Clone)]
enum AddTarget {
    /// `@lpm.dev/owner.name` — the only form that means lpm.dev.
    Lpm(PackageName),
    /// Anything else npm accepts: bare names (`react`, `lodash.merge`),
    /// scoped names (`@juggle/resize-observer`, `@private/internal-pkg`).
    /// Stored verbatim so output renders the user's spec, not a
    /// reconstruction.
    Npm { spec: String },
}

impl AddTarget {
    /// Human-readable identity for `output::info` / `println!`.
    fn display(&self) -> String {
        match self {
            Self::Lpm(pkg) => pkg.scoped(),
            Self::Npm { spec } => spec.clone(),
        }
    }

    /// Identity for the `package.name` field in `--json` output.
    /// Same shape as `display()` today; kept as a separate method so
    /// JSON consumers can be evolved independently of human output.
    fn json_name(&self) -> String {
        self.display()
    }

    /// Identity passed to routing helpers (`route_for_package`,
    /// `download_tarball_routed`). For `Lpm`, the scoped form is what
    /// `RouteTable` matches on (`@lpm.dev/*` → forces `LpmWorker`); for
    /// `Npm`, the original spec is what npm/`.npmrc` route on.
    fn route_name(&self) -> String {
        self.display()
    }
}

/// Output of `resolve_add_target`: the parsed target identity, an
/// optional explicit version spec (everything after the trailing `@`),
/// and any inline `?key=val&key=val` config picked up from the input.
type ResolvedAddInput = (AddTarget, Option<String>, HashMap<String, String>);

/// Resolve a user-supplied `lpm add <spec>` argument to an `AddTarget`,
/// stripping any `@version` suffix and `?key=val` query params.
///
/// Phase 60 (D-naming-rule): bare/dotted/non-`@lpm.dev/` inputs flow to
/// `AddTarget::Npm` verbatim. The pre-Phase-60 dotted-name auto-prepend
/// at `parse_package_ref` (`tolga.foo` → `@lpm.dev/tolga.foo`) is gone:
/// it silently rewrote real npm packages like `lodash.merge`,
/// `lodash.debounce`, `lodash.throttle` into the `@lpm.dev/` namespace
/// where they don't exist. Per the firm rule "only `@lpm.dev/owner.name`
/// identifies an lpm.dev-hosted package," the new resolver does no
/// rewriting outside that scope.
fn resolve_add_target(spec: &str) -> Result<ResolvedAddInput, LpmError> {
    let mut inline_config = HashMap::new();

    // Split on `?` for query params (e.g., `pkg?component=dialog`).
    let rest = if let Some(pos) = spec.find('?') {
        let q = &spec[pos + 1..];
        for param in q.split('&') {
            if let Some(eq) = param.find('=') {
                inline_config.insert(param[..eq].to_string(), param[eq + 1..].to_string());
            }
        }
        &spec[..pos]
    } else {
        spec
    };

    // Split on `@` for version, handling scoped packages whose first
    // char is also `@`.
    let (name, version) = if let Some(stripped) = rest.strip_prefix('@') {
        // `@scope/name@version` — find the `@` that follows the scope.
        if let Some(at_pos) = stripped.find('@') {
            let at_pos = at_pos + 1; // +1 to account for the stripped '@'
            (
                rest[..at_pos].to_string(),
                Some(rest[at_pos + 1..].to_string()),
            )
        } else {
            (rest.to_string(), None)
        }
    } else if let Some(at_pos) = rest.find('@') {
        (
            rest[..at_pos].to_string(),
            Some(rest[at_pos + 1..].to_string()),
        )
    } else {
        (rest.to_string(), None)
    };

    if name.is_empty() {
        return Err(LpmError::InvalidPackageName(format!(
            "could not parse package name from '{spec}'"
        )));
    }

    // Identity rule: only `@lpm.dev/` inputs route through `PackageName`.
    // Everything else stays verbatim and flows through npm/`.npmrc`.
    let target = if name.starts_with("@lpm.dev/") {
        AddTarget::Lpm(PackageName::parse(&name)?)
    } else {
        AddTarget::Npm { spec: name }
    };

    Ok((target, version, inline_config))
}

/// Add source files from a package into your project (shadcn-style).
///
/// Always does source delivery: download, extract, copy files.
/// For managed dependency installation, use `lpm install` instead.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    package_spec: &str,
    target_path: Option<&str>,
    yes: bool,
    json_output: bool,
    force: bool,
    dry_run: bool,
    no_install_deps: bool,
    no_skills: bool,
    no_editor_setup: bool,
    pm: &str,
    alias_override: Option<&str>,
    swift_target: Option<&str>,
) -> Result<(), LpmError> {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());

    // Step 1: Resolve package reference into AddTarget (Phase 60 D-decoupling).
    // `@lpm.dev/owner.name` → AddTarget::Lpm(PackageName); everything else
    // → AddTarget::Npm { spec } verbatim. No dotted-name auto-prepend.
    let (target, version_spec, mut inline_config) = resolve_add_target(package_spec)?;

    // Typosquatting check: warn if the name looks like a popular package misspelling.
    // Skip if the exact package is already in the lockfile — the user has already accepted it.
    let display_for_typosquat = target.display();
    if !json_output
        && let Some(warning) = should_warn_typosquatting(&display_for_typosquat, project_dir)
    {
        output::warn(&format!(
            "'{}' is similar to popular package '{}'. Did you mean '{}'?",
            warning.input, warning.similar, warning.similar
        ));
    }

    if !json_output {
        output::info(&format!("Adding {}", target.display().bold()));
    }

    // Step 2: `.npmrc` setup (Phase 60.0.c — mirrors install.rs:3295-3445).
    //
    // Build the RouteTable BEFORE any network call so:
    // - fatal `${MISSING_VAR}` errors abort early (npm parity);
    // - advisory warnings surface in non-JSON mode;
    // - the `strict-ssl=false` security warning escapes `--json` (stderr);
    // - TLS overrides (`cafile=`, `strict-ssl=false`) take effect on the
    //   metadata + tarball fetches via `with_tls_overrides`.
    let route_table = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;
    if !json_output {
        for w in route_table.npmrc_warnings() {
            output::warn(w);
        }
    }
    // strict-ssl=false is a SECURITY signal — emit unconditionally (stderr),
    // matching install.rs:3306-3321.
    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        output::warn(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is \
             DISABLED for this `lpm add` across ALL registries. This is a \
             security risk.",
            tagged.source, tagged.line
        ));
    }
    // Phase 58.3 — request-aware eager-build: `lpm add <spec>`'s
    // top-level request is exactly `{spec}`. The fetch site below
    // (`get_npm_metadata_routed(spec, …)`) and version resolution
    // (`resolve_version_spec(version_spec)`) both operate on the
    // raw `target` and `version_spec` strings — npm aliases like
    // `lpm add foo@npm:react@18` are NOT currently supported by
    // those paths (they'd route + fetch as `foo`, not `react`). So
    // the eager-set inputs mirror actual fetch behavior: the local
    // target name, no alias unwrapping. If alias support lands for
    // `lpm add` later, the alias-target unwrap should be applied
    // here AND in the fetch + resolve paths in lockstep.
    let top_level_specs: Vec<String> = vec![target.display()];
    let eager_origins = route_table.effective_registry_origins(
        &top_level_specs,
        client.base_url(),
        client.npm_registry_url(),
    );
    let owned_client = client
        .clone_with_config()
        .with_tls_overrides_for(route_table.tls_overrides(), &eager_origins)?;
    let client = &owned_client;
    // Phase 58.3 — install-start summary of effective TLS overrides
    // (mirrors install.rs:3859 wiring).
    if !json_output && let Some(line) = client.render_effective_tls_summary() {
        output::info(&line);
    }

    // Step 3: Routed metadata fetch (Phase 60.0.d).
    // - AddTarget::Lpm → lpm.dev metadata API (LpmWorker route, forced
    //   by `@lpm.dev/` prefix in `RouteTable::route_for_package`).
    // - AddTarget::Npm → routed npm metadata via .npmrc / NpmDirect /
    //   LpmWorker per the route table.
    let metadata = match &target {
        AddTarget::Lpm(pkg) => client.get_package_metadata(pkg).await?,
        AddTarget::Npm { spec } => {
            let route = route_table.route_for_package(spec);
            client.get_npm_metadata_routed(spec, route).await?
        }
    };

    // Phase 60.0.e — version-spec resolution covers dist-tags + semver
    // ranges (e.g., `react@beta`, `lodash@^4`). Pre-Phase-60 code did a
    // pure HashMap lookup which fails for any non-literal spec.
    let version = if let Some(v) = &version_spec {
        metadata.resolve_version_spec(v)?
    } else {
        metadata
            .latest_version_tag()
            .ok_or_else(|| LpmError::NotFound("no latest version".into()))?
            .to_string()
    };

    let ver_meta = metadata
        .version(&version)
        .ok_or_else(|| LpmError::NotFound(format!("version {version} not found")))?;

    if !json_output {
        output::info(&format!(
            "Downloading {}@{}",
            target.display(),
            version.bold()
        ));
    }

    // Step 3.1: File-spool tarball download (Phase 60.0.d, D1 + D2).
    // Uses `download_tarball_routed` so:
    //   - LpmWorker / NpmDirect → no-auth file-spool;
    //   - Custom (`.npmrc`-declared private registry) → auth-attached
    //     file-spool, no LPM session bearer leak to the custom origin.
    // File-spool gives bounded memory (`MAX_COMPRESSED_TARBALL_SIZE`,
    // 500 MB) for free — `lpm add typescript` (~22 MB) and the worst-
    // case `lpm add @scope/giant-fixture` no longer load the full
    // tarball into RAM.
    let tarball_url = ver_meta
        .tarball_url()
        .ok_or_else(|| LpmError::NotFound("no tarball URL".into()))?;
    let downloaded = client
        .download_tarball_routed(&route_table, &target.route_name(), tarball_url)
        .await?;

    // Step 3.2: Verify integrity. Fast path: SRI compare against the
    // SHA-512 hash already computed during download. Slow path: stream-
    // verify from the temp file (covers non-sha512 expected values).
    // Mirrors install.rs:8156-8170.
    if let Some(integrity) = ver_meta.integrity() {
        if downloaded.sri != integrity
            && let Err(e) = lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
        {
            return Err(LpmError::Registry(format!(
                "integrity verification failed for {}@{}: {e}",
                target.display(),
                version
            )));
        }
        if !json_output {
            output::info("Integrity verified");
        }
    } else {
        tracing::debug!(
            "no integrity hash for {}@{}, skipping verification",
            target.display(),
            version
        );
    }

    // Step 3.3: Extract tarball from the spooled file (bounded-memory
    // path).
    let temp_dir = tempfile::tempdir().map_err(LpmError::Io)?;
    let extracted_paths =
        lpm_extractor::extract_tarball_from_file(downloaded.file.path(), temp_dir.path())?;

    // Step 3.4: Validate extracted paths for path traversal (extraction-
    // side check; the user-side write-time containment check happens
    // below in Step 8 via `resolve_safe_dest` — see Phase 60.0.f).
    validate_extracted_paths(&extracted_paths, temp_dir.path())?;

    // Step 4: Read lpm.config.json
    let lpm_config = read_lpm_config(temp_dir.path());

    // Step 4.05: Non-interactive simple-path guard (Phase 60.1.5).
    //
    // The simple path (no `lpm.config.json`) is a download-manager flow:
    // copy source files into a user-chosen directory, no auto-deps. In
    // interactive mode the user gets a prompt for the target dir. In
    // non-interactive mode (`--yes`, `--json`, or non-TTY) without
    // `--path`, defaulting silently into a heuristic-detected
    // `components/` is a CI/automation footgun — the user has no chance
    // to confirm where 3rd-party source landed. Refuse explicitly.
    //
    // Swift packages still hit this branch via the rich-config check
    // below (every Swift package on lpm.dev has a `lpm.config.json`),
    // so the Swift auto-default at `resolve_target_dir` is unaffected.
    let is_non_interactive = yes || json_output || !is_tty;
    if lpm_config.is_none() && target_path.is_none() && is_non_interactive {
        return Err(LpmError::Registry(
            "non-interactive mode (--yes, --json, or non-TTY) requires --path \
             for packages without lpm.config.json: cannot safely default a \
             target directory for arbitrary source copy"
                .into(),
        ));
    }

    // Step 4.1: Config schema interactive prompts
    if let Some(config) = &lpm_config
        && let Some(schema) = config.get("configSchema").and_then(|s| s.as_object())
    {
        if !yes && !json_output && is_tty {
            for (key, field) in schema {
                // Skip if already provided via inline config
                if inline_config.contains_key(key) {
                    continue;
                }

                let field_type = field
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("string");
                let label = field.get("label").and_then(|l| l.as_str()).unwrap_or(key);
                let default_val = config
                    .get("defaultConfig")
                    .and_then(|dc| dc.get(key))
                    .and_then(json_value_to_config_string)
                    .or_else(|| field.get("default").and_then(json_value_to_config_string))
                    .unwrap_or_default();

                match field_type {
                    "boolean" => {
                        let result = cliclack::confirm(label)
                            .initial_value(default_val == "true")
                            .interact()
                            .map_err(prompt_err)?;
                        inline_config.insert(key.clone(), result.to_string());
                    }
                    "select" => {
                        let multi = field
                            .get("multiSelect")
                            .and_then(|m| m.as_bool())
                            .unwrap_or(false);
                        // Parse options as (value, label) pairs
                        let options: Vec<(String, String)> = field
                            .get("options")
                            .and_then(|o| o.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| {
                                        if let Some(s) = v.as_str() {
                                            Some((s.to_string(), s.to_string()))
                                        } else {
                                            let value =
                                                v.get("value").and_then(|vv| vv.as_str())?;
                                            let label_str = v
                                                .get("label")
                                                .and_then(|l| l.as_str())
                                                .unwrap_or(value);
                                            Some((value.to_string(), label_str.to_string()))
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        if options.is_empty() {
                            continue;
                        }

                        let values: Vec<String> = options.iter().map(|(v, _)| v.clone()).collect();

                        if multi {
                            let mut ms = cliclack::multiselect(label);
                            for (value, label_str) in &options {
                                ms = ms.item(value.clone(), label_str, "");
                            }
                            // Default all selected
                            ms = ms.initial_values(values);
                            let selected_values: Vec<String> = ms.interact().map_err(prompt_err)?;
                            let selected: Vec<&str> =
                                selected_values.iter().map(|s| s.as_str()).collect();
                            inline_config.insert(key.clone(), selected.join(","));
                        } else {
                            let default_idx = values
                                .iter()
                                .position(|v| *v == default_val.as_str())
                                .unwrap_or(0);
                            let mut sel = cliclack::select(label);
                            for (i, (value, label_str)) in options.iter().enumerate() {
                                sel = sel.item(value.clone(), label_str, "");
                                if i == default_idx {
                                    sel = sel.initial_value(value.clone());
                                }
                            }
                            let chosen: String = sel.interact().map_err(prompt_err)?;
                            inline_config.insert(key.clone(), chosen);
                        }
                    }
                    _ => {
                        // string / text input
                        let value: String = cliclack::input(label)
                            .default_input(&default_val)
                            .interact()
                            .map_err(prompt_err)?;
                        inline_config.insert(key.clone(), value);
                    }
                }
            }
        } else if yes {
            // --yes: use defaults for required fields that aren't provided
            for (key, field) in schema {
                if inline_config.contains_key(key) {
                    continue;
                }
                let is_required = field
                    .get("required")
                    .and_then(|r| r.as_bool())
                    .unwrap_or(false);
                if is_required {
                    let default_val = config
                        .get("defaultConfig")
                        .and_then(|dc| dc.get(key))
                        .and_then(json_value_to_config_string)
                        .or_else(|| field.get("default").and_then(json_value_to_config_string))
                        .unwrap_or_default();
                    inline_config.insert(key.clone(), default_val);
                }
            }
        }
    }

    // Step 5: Detect ecosystem and determine target
    let ecosystem = lpm_config
        .as_ref()
        .and_then(|c| c.get("ecosystem").and_then(|v| v.as_str()))
        .unwrap_or("js");

    // Step 5.1: Interactive target directory selection
    let target_dir = if target_path.is_some() {
        resolve_target_dir(project_dir, target_path, ecosystem, swift_target)?
    } else if !yes && !json_output && is_tty && ecosystem != "swift" {
        let default_dir = detect_default_install_dir(project_dir, ecosystem);
        let default_str = default_dir
            .strip_prefix(project_dir)
            .unwrap_or(&default_dir)
            .display()
            .to_string();

        let target: String = cliclack::input("Install directory")
            .default_input(&default_str)
            .placeholder(&default_str)
            .interact()
            .map_err(prompt_err)?;

        project_dir.join(target)
    } else {
        resolve_target_dir(project_dir, target_path, ecosystem, swift_target)?
    };

    if !json_output {
        let rel = target_dir.strip_prefix(project_dir).unwrap_or(&target_dir);
        output::info(&format!(
            "Installing to {}",
            rel.display().to_string().bold()
        ));
    }

    // Step 6: Build file list (config-based or lpm.source fallback or all files)
    let files = if let Some(config) = &lpm_config {
        if let Some(files_arr) = config.get("files").and_then(|f| f.as_array()) {
            filter_config_files(temp_dir.path(), files_arr, &inline_config)?
        } else {
            collect_source_with_fallback(temp_dir.path())?
        }
    } else {
        collect_source_with_fallback(temp_dir.path())?
    };

    if files.is_empty() {
        return Err(LpmError::Registry("no files to install".into()));
    }

    // Step 6.1: Dry-run mode — show what would happen and exit
    if dry_run {
        return handle_dry_run(
            project_dir,
            &target_dir,
            &files,
            force,
            &target,
            &version,
            &lpm_config,
            &inline_config,
            ecosystem,
            temp_dir.path(),
            json_output,
        );
    }

    // Step 6.2: Preflight — refuse to copy a deps-declaring source
    // package into a project with no `package.json` (Phase 64 #9.4).
    //
    // Without a manifest, the dep entries the source declares have
    // nowhere to land; the user would end up with copied source
    // files importing packages they can't install. Hard-error here,
    // BEFORE any user-side side effects (Step 7 prompts, Step 8
    // file copies, Step 9 dep install). The remediation hint points
    // at `lpm init` / `npm init -y` so the user knows the fix; the
    // `--no-install-deps` escape preserves the existing "I'll
    // handle deps myself" path.
    preflight_no_manifest_with_deps(
        project_dir,
        temp_dir.path(),
        &lpm_config,
        &inline_config,
        no_install_deps,
    )?;

    // Step 7: Prepare import rewriting
    let author_alias = lpm_config
        .as_ref()
        .and_then(|c| c.get("importAlias"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Detect buyer alias from tsconfig/jsconfig, then prompt to confirm.
    // --alias flag overrides all detection and prompting.
    let buyer_alias = if ecosystem == "swift" {
        // Swift uses `import ModuleName`, not path aliases
        None
    } else if let Some(explicit) = alias_override {
        // --alias flag takes precedence
        let alias = if explicit.ends_with('/') {
            explicit.to_string()
        } else {
            format!("{explicit}/")
        };
        Some(alias)
    } else {
        let detected = detect_buyer_alias(project_dir);

        if !yes && !json_output && is_tty {
            // Build a sensible default: detected alias + target relative path
            let target_rel = target_dir
                .strip_prefix(project_dir)
                .unwrap_or(&target_dir)
                .to_string_lossy()
                .to_string();
            let default_alias = if let Some(ref alias) = detected {
                format!("{}{}", alias, target_rel)
            } else if !target_rel.is_empty() {
                format!("@/{}", target_rel)
            } else {
                String::new()
            };

            let input: String = cliclack::input(
                "Import alias for this directory? (leave empty for relative imports)",
            )
            .default_input(&default_alias)
            .placeholder(&default_alias)
            .required(false)
            .interact()
            .map_err(prompt_err)?;

            let trimmed = input.trim();
            if trimmed.is_empty() {
                None
            } else {
                let alias = if trimmed.ends_with('/') {
                    trimmed.to_string()
                } else {
                    format!("{trimmed}/")
                };
                Some(alias)
            }
        } else {
            detected
        }
    };

    // Build src->dest map and file sets for import resolution
    let src_to_dest: HashMap<String, String> = files.iter().cloned().collect();
    let src_files: HashSet<String> = files.iter().map(|(s, _)| s.clone()).collect();
    let dest_files: HashSet<String> = files.iter().map(|(_, d)| d.clone()).collect();

    // Step 7.5: Set up the rollback transaction (Phase 64 finding #9.3).
    //
    // Open ONE `ManifestTransaction` covering Step 8's source-file
    // copies AND Step 9's dependency mutations + trailing install. The
    // transaction commits right after Step 9.1; Steps 10-12 (Swift
    // recursion, output, skills) intentionally run outside the tx
    // because they have their own scopes (Swift: recursive `run()`
    // owns its own tx; output: read-only; skills: best-effort,
    // non-fatal by contract).
    //
    // Path discipline (Phase 64 #9.3 second-pass audit). Validation
    // happens via [`resolve_safe_dest_validate`] (pure, no mkdir);
    // the mkdir + post-mkdir canonicalize step
    // ([`prepare_safe_dest_parent`]) runs immediately after,
    // BEFORE the snapshot opens, so the canonicalized dest path is
    // pinned and identical between the snapshot read and the Step 8
    // write. Pre-fix, the snapshot tracked the pre-canonicalize path
    // while Step 8 wrote to a different (canonical) path — when an
    // intermediate symlink resolved differently between the two,
    // rollback would restore the wrong file. Sliding the mkdir
    // earlier means freshly-created parent directories live outside
    // the rollback boundary (a rolled-back failure leaves empty
    // parents on disk); that's a documented trade-off.
    let mut copied = 0;
    let mut skipped = 0;
    let mut file_actions: Vec<(String, String, String)> = Vec::new(); // (src, dest, action)
    std::fs::create_dir_all(&target_dir)?;
    let target_root_canonical = target_dir.canonicalize().map_err(|e| {
        LpmError::Registry(format!(
            "could not canonicalize target directory '{}': {e}",
            target_dir.display()
        ))
    })?;

    // Per-file: validate the dest_rel (no side effect), materialize +
    // canonicalize the parent (mkdir + post-canonicalize containment),
    // then compose the canonical-pinned final dest path. Step 8
    // reads, conflict-checks, and writes through this exact path; the
    // tx snapshots it too. Snapshot path == write path; no TOCTOU
    // window between snapshot and write.
    let final_dest_paths: Vec<PathBuf> = files
        .iter()
        .map(|(_, dest_rel)| {
            let validated =
                resolve_safe_dest_validate(&target_root_canonical, &target_dir, dest_rel)?;
            let parent = validated.parent().ok_or_else(|| {
                LpmError::Registry(format!(
                    "destination '{}' has no parent",
                    validated.display()
                ))
            })?;
            let parent_canonical = prepare_safe_dest_parent(parent, &target_root_canonical)?;
            let file_name = validated.file_name().ok_or_else(|| {
                LpmError::Registry(format!(
                    "destination '{}' has no file name",
                    validated.display()
                ))
            })?;
            Ok::<PathBuf, LpmError>(parent_canonical.join(file_name))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Resolve `--pm auto` to a concrete PM so the tx can snapshot the
    // right per-PM lockfile alongside the LPM lockfiles.
    let pkg_json_path = project_dir.join("package.json");
    let lpm_lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lpm_lock_bin_path = lpm_lock_path.with_extension("lockb");
    let install_hash_path = project_dir.join(".lpm").join("install-hash");
    let effective_pm = if pm == "auto" {
        detect_package_manager(project_dir)
    } else {
        pm.to_string()
    };
    let pm_lockfiles = pm_lockfile_paths(&effective_pm, project_dir);

    // Optional snapshot list: manifest, LPM lockfiles, the selected
    // PM's lockfile(s), and every canonical-pinned dest path Step 8
    // may touch. Manifest is `optional` (not `required`) because a
    // bare-template `lpm add` against a project with no `package.json`
    // is a valid path; the snapshot tolerates the absence and the
    // dep-install step warns separately.
    let mut optional_snapshot: Vec<&Path> = vec![
        pkg_json_path.as_path(),
        lpm_lock_path.as_path(),
        lpm_lock_bin_path.as_path(),
    ];
    for p in &pm_lockfiles {
        optional_snapshot.push(p.as_path());
    }
    for p in &final_dest_paths {
        optional_snapshot.push(p.as_path());
    }
    let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
        &[],
        &optional_snapshot,
        &[install_hash_path.as_path()],
    )
    .map_err(|e| LpmError::Registry(format!("failed to snapshot install state: {e}")))?;

    // Step 8: Copy files to target (with import rewriting and conflict
    // resolution). Inside the tx scope — any `?` error from here
    // through Step 9.1 drops the tx and rolls back every snapshotted
    // path (overwrites restored to original bytes; new files deleted)
    // plus invalidates `.lpm/install-hash` so the next install
    // re-derives state from a clean manifest.
    //
    // Phase 60.0.f (D6) — destination-side path containment.
    // Pre-Phase-60, the only path-traversal check ran at extraction
    // against the temp dir; the user-side write at `target_dir.join(dest_rel)`
    // had no second containment check. For arbitrary npm tarballs (the
    // whole point of Phase 60), that's the wrong threat model: a
    // malicious or buggy `dest_rel` could escape `target_dir` after
    // following an existing user-side symlink. The validate +
    // prepare phases above canonicalize the parent of every write,
    // refuse to write through existing symlinks, and reject any
    // destination whose canonical parent escapes
    // `target_root_canonical`. The Step 8 loop reads, conflict-checks,
    // and writes through `final_dest_paths[i]` — the canonical-pinned
    // path computed above.
    for ((src_rel, dest_rel), dest_path) in files.iter().zip(final_dest_paths.iter()) {
        let src_path = temp_dir.path().join(src_rel);

        if !src_path.exists() {
            continue;
        }

        // Try to read as text for import rewriting
        let content = std::fs::read_to_string(&src_path).ok();
        let rewritten = content.as_deref().and_then(|text| {
            // Only rewrite JS/TS files
            let ext = src_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
                return None;
            }
            crate::import_rewriter::rewrite_imports(
                text,
                src_rel,
                dest_rel,
                author_alias.as_deref(),
                buyer_alias.as_deref(),
                &src_to_dest,
                &src_files,
                &dest_files,
            )
        });

        let final_content = rewritten.as_deref().or(content.as_deref());

        let dest_existed = dest_path.exists();

        // Check for conflicts using diff-aware resolution
        if dest_existed {
            let action =
                handle_file_conflict(&src_path, dest_path, final_content, force, yes, json_output)?;
            match action {
                ConflictAction::Skip => {
                    skipped += 1;
                    file_actions.push((src_rel.clone(), dest_rel.clone(), "skip".to_string()));
                    continue;
                }
                ConflictAction::Overwrite => {
                    // Fall through to write
                }
            }
        }

        // Write (rewritten text or copy binary)
        if let Some(text) = final_content {
            std::fs::write(dest_path, text)?;
        } else {
            std::fs::copy(&src_path, dest_path)?;
        }
        copied += 1;
        file_actions.push((
            src_rel.clone(),
            dest_rel.clone(),
            if dest_existed { "overwrite" } else { "create" }.to_string(),
        ));
    }

    // Step 9: Handle dependencies (Phase 60.1).
    //
    // Gate: only when `lpm.config.json` is present. Pre-Phase-60 the
    // legacy fallback at `handle_dependencies` would read the package's
    // own `package.json#dependencies + peerDependencies` whenever
    // `lpm.config.json#dependencies` was absent — fine for source-shape
    // packages on lpm.dev, but a footgun for arbitrary npm tarballs:
    // `lpm add typescript --yes` would silently bloat the user's
    // `package.json` with TypeScript's transitive deps. Simple-path
    // (no `lpm.config.json`) keeps the download-manager contract:
    // copy bytes, surface external imports, let the user install deps
    // themselves.
    let dep_count = if !no_install_deps && lpm_config.is_some() {
        handle_dependencies(
            client,
            &route_table,
            project_dir,
            temp_dir.path(),
            &lpm_config,
            &inline_config,
            ecosystem,
            yes,
            json_output,
            &effective_pm,
        )
        .await?
    } else if !no_install_deps && lpm_config.is_none() {
        // Simple path → no auto-install. The bare-imports notice
        // below surfaces what the user should add themselves.
        0
    } else {
        let count = count_dependencies(&lpm_config, &inline_config, temp_dir.path())?;
        if count > 0 && !json_output {
            output::info(&format!(
                "Skipped {} dependencies (--no-install-deps)",
                count
            ));
        }
        0
    };

    // Step 9.1: Bare-imports notice — Phase 60.1 D4.
    //
    // Simple path (no `lpm.config.json`) only: walk every JS/TS file we
    // just copied, collect external/bare specifiers, and surface them
    // so the user knows which deps they need to install themselves.
    // Anti-drift: shares the `SpecifierKind` classifier with
    // `import_rewriter::rewrite_imports` so "bare" means the same thing
    // in both places.
    let external_imports: Vec<String> = if lpm_config.is_none() {
        let mut collected: HashSet<String> = HashSet::new();
        for (src_rel, _dest_rel) in &files {
            let src_path = temp_dir.path().join(src_rel);
            let ext = src_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&src_path) {
                collected.extend(crate::import_rewriter::collect_bare_specifiers(
                    &text,
                    author_alias.as_deref(),
                ));
            }
        }
        let mut sorted: Vec<String> = collected.into_iter().collect();
        sorted.sort();
        sorted
    } else {
        Vec::new()
    };
    if !external_imports.is_empty() && !json_output {
        output::info(&format!(
            "Source uses external imports: {}\n  Make sure these are in your project's dependencies.",
            external_imports.join(", "),
        ));
    }

    // Step 9.2: Commit the rollback transaction (Phase 64 finding #9.3).
    //
    // Steps 8 + 9 + 9.1 (file copy, dep mutation, trailing install,
    // bare-imports read-only notice) all completed without error, so
    // the snapshotted bytes are stale and the project's new state is
    // the one we want to keep.
    //
    // The commit lands BEFORE Step 10 (Swift recursion) on purpose:
    // `handle_swift_lpm_deps` recursively re-enters this function for
    // each Swift dep, and each recursive `lpm add` opens its own tx.
    // If the outer tx stayed open across that boundary, a recursive
    // failure could roll back the root package's already-applied
    // mutations while leaving the recursive `lpm add`'s side effects
    // intact — a worse split-brain than no rollback at all. Step 11
    // output and Step 12 skills are intentionally outside the tx for
    // the same reason: each owns a separate, narrower contract.
    tx.commit();

    // Step 10: For Swift, handle recursive LPM dependencies
    if ecosystem == "swift" {
        handle_swift_lpm_deps(
            client,
            project_dir,
            ver_meta,
            yes,
            json_output,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            pm,
        )
        .await?;
    }

    // Step 11: Output
    if json_output {
        let json = serde_json::json!({
            "success": true,
            "package": {
                "name": target.json_name(),
                "version": version,
                "ecosystem": ecosystem,
            },
            "files": file_actions.iter().map(|(src, dest, action)| {
                serde_json::json!({
                    "src": src,
                    "dest": dest,
                    "action": action,
                })
            }).collect::<Vec<_>>(),
            "install_path": target_dir.strip_prefix(project_dir).unwrap_or(&target_dir).display().to_string(),
            "files_copied": copied,
            "files_skipped": skipped,
            "dependencies_installed": dep_count,
            "external_imports": external_imports,
            "config": inline_config,
            "alias": buyer_alias,
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!();
        output::success(&format!(
            "Added {}@{} ({} files)",
            target.display().bold(),
            version,
            copied,
        ));
        if skipped > 0 {
            println!(
                "  {} files unchanged (skipped)",
                skipped.to_string().dimmed()
            );
        }
        if dep_count > 0 {
            println!(
                "  {} dependencies installed",
                dep_count.to_string().dimmed()
            );
        }

        // Security check for source delivery too
        if ver_meta.has_security_issues() {
            print_security_warnings(&target.display(), &version, ver_meta);
        }
        println!();
    }

    // Step 12: Install skills if this is an LPM package (respects --no-skills).
    //
    // Why @lpm.dev-only: lpm.dev runs LLM security scans on shipped skill
    // content at publish time, so the .md files we extract here are
    // attested. Arbitrary npm packages are not scanned, so we don't
    // extract their skills — opt-in npm-skills support would need an
    // explicit `--allow-skills` flag and an `lpm.config.json#skills`
    // declaration (deferred per the Phase 60 non-goals).
    if !no_skills && let AddTarget::Lpm(pkg) = &target {
        let short_name = pkg.short();
        match client.get_skills(&short_name, None).await {
            Ok(response) if !response.skills.is_empty() => {
                let skills_dir = project_dir.join(".lpm").join("skills").join(&short_name);
                let _ = std::fs::create_dir_all(&skills_dir);

                let mut installed = 0;
                for skill in &response.skills {
                    let content = skill
                        .raw_content
                        .as_deref()
                        .or(skill.content.as_deref())
                        .unwrap_or("");
                    if !content.is_empty() {
                        let path = skills_dir.join(format!("{}.md", skill.name));
                        let _ = std::fs::write(&path, content);
                        installed += 1;
                    }
                }

                if installed > 0 && !json_output {
                    output::info(&format!(
                        "Installed {installed} agent skill(s) for {short_name}"
                    ));

                    // Ensure .gitignore includes .lpm/skills/
                    crate::commands::install::ensure_skills_gitignore(project_dir);

                    // Auto-integrate with editors (respects --no-editor-setup)
                    if !no_editor_setup {
                        let integrations = crate::editor_skills::auto_integrate_skills(project_dir);
                        for msg in &integrations {
                            output::info(msg);
                        }
                    }
                }
            }
            _ => {} // No skills or API error -- skip silently
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Path traversal validation
// ---------------------------------------------------------------------------

/// Validate that all extracted file paths stay within the target directory.
///
/// Prevents malicious tarballs from writing outside the extraction directory
/// using `../` or symlink tricks.
fn validate_extracted_paths(files: &[PathBuf], target_dir: &Path) -> Result<(), LpmError> {
    let target_canonical = target_dir
        .canonicalize()
        .unwrap_or_else(|_| target_dir.to_path_buf());

    for file in files {
        let resolved = target_dir.join(file);
        let canonical = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
        if !canonical.starts_with(&target_canonical) {
            return Err(LpmError::Registry(format!(
                "path traversal detected: '{}' escapes target directory",
                file.display()
            )));
        }
    }
    Ok(())
}

/// Compose [`resolve_safe_dest_validate`] + [`prepare_safe_dest_parent`]
/// for the test suite that exercises both phases as a single call.
///
/// Production callers (`run`'s Step 8) hold the two phases apart so a
/// `ManifestTransaction` snapshot opens between validation and the
/// mkdir-during-copy step. See `resolve_safe_dest_validate` for the
/// threat model and Phase 60.0.f / D6 background.
#[cfg(test)]
fn resolve_safe_dest(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
) -> Result<PathBuf, LpmError> {
    let dest = resolve_safe_dest_validate(target_root_canonical, target_dir, dest_rel)?;
    let parent = dest.parent().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no parent", dest.display()))
    })?;
    let parent_canonical = prepare_safe_dest_parent(parent, target_root_canonical)?;
    let file_name = dest.file_name().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no file name", dest.display()))
    })?;
    Ok(parent_canonical.join(file_name))
}

/// Validate a write destination under a canonical target root, without
/// any filesystem side effects.
///
/// Phase 60.0.f (D6) — destination-side containment for `lpm add`.
/// `validate_extracted_paths` above proves the tarball didn't escape
/// extraction; this function proves the user-side write doesn't escape
/// `target_dir` either, including via existing symlinks.
///
/// **Ordering matters.** Every check that can establish "this destination
/// is unsafe" runs BEFORE any filesystem mutation. Pre-fix, `create_dir_all`
/// ran before the canonical-parent containment check, so a malicious
/// `dest = "../../escape/evil.txt"` or an absolute `dest = "/tmp/elsewhere/evil.txt"`
/// would create the directory outside the target before erroring on the
/// file write. The directory side-effect was the bug; the file write was
/// already blocked.
///
/// Defense in depth, in order:
/// 1. **Lexical absolute-path reject.** `Path::join` replaces the base
///    when the join argument is absolute, so an absolute `dest_rel`
///    would route the write to whatever path the tarball asked for.
///    Reject up-front, no filesystem touch.
/// 2. **Lexical `..` / root-component reject.** Any `dest_rel` containing
///    `ParentDir` (`..`), `RootDir` (`/`), or a `Prefix` (Windows drive)
///    component cannot legitimately resolve to a path under `target_dir`.
///    Reject up-front, no filesystem touch. This kills the entire
///    `../../escape` attack class before any mkdir runs.
/// 3. **Existing-symlink reject.** If `dest_rel` resolves to an existing
///    symlink, refuse to follow/overwrite it — even if it points inside
///    target today, it can be repointed before the write.
/// 4. **Pre-mkdir ancestor canonicalization.** Walk up from the
///    destination's parent until we hit an existing ancestor; canonicalize
///    that and require it to live under `target_root_canonical`. Catches
///    the case where some intermediate dir is itself a symlink pointing
///    outside (e.g., `target_dir/foo` → `/tmp/elsewhere`,
///    `dest_rel = "foo/bar.txt"`).
///
/// The mkdir + post-mkdir re-canonicalize pair lives in
/// [`prepare_safe_dest_parent`]. `lpm add`'s Step 8 splits the two so a
/// `ManifestTransaction` snapshot can record every validated dest path
/// before any directory side effects happen.
fn resolve_safe_dest_validate(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
) -> Result<PathBuf, LpmError> {
    let rel_path = Path::new(dest_rel);

    // Step 1: Reject absolute `dest_rel`. `Path::join(absolute)` would
    // discard `target_dir` and route the write to the absolute path.
    if rel_path.is_absolute() {
        return Err(LpmError::Registry(format!(
            "destination '{dest_rel}' is absolute; only paths relative to the target are allowed"
        )));
    }

    // Step 2: Reject `..`, root, and Windows-prefix components. With this
    // gate, the joined path cannot lexically escape `target_dir`, and the
    // mkdir later cannot create directories outside the target — even
    // if the canonical-parent check that follows would later catch the
    // escape attempt.
    for component in rel_path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(LpmError::Registry(format!(
                    "destination '{dest_rel}' contains '..'; \
                     parent-directory references are not allowed in destination paths"
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(LpmError::Registry(format!(
                    "destination '{dest_rel}' contains a root or drive component; \
                     only relative paths under the target are allowed"
                )));
            }
            _ => {}
        }
    }

    let dest = target_dir.join(rel_path);

    // Step 3: Refuse to overwrite/follow an existing symlink at the
    // destination itself. `symlink_metadata` does NOT follow links.
    if let Ok(meta) = std::fs::symlink_metadata(&dest)
        && meta.file_type().is_symlink()
    {
        return Err(LpmError::Registry(format!(
            "destination '{}' is a symlink; refusing to write through it",
            dest.display()
        )));
    }

    let parent = dest.parent().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no parent", dest.display()))
    })?;

    // Step 4: Pre-mkdir ancestor canonicalization — walk up until we hit
    // a path that exists, canonicalize THAT (following any symlinks),
    // and require it to live under `target_root_canonical`. This catches
    // the case where an intermediate directory inside the target is
    // itself a symlink pointing outside.
    let mut probe: PathBuf = parent.to_path_buf();
    let canonical_existing_ancestor = loop {
        match probe.canonicalize() {
            Ok(c) => break c,
            Err(_) => {
                if !probe.pop() {
                    return Err(LpmError::Registry(format!(
                        "could not find any existing ancestor of '{}'",
                        parent.display()
                    )));
                }
            }
        }
    };
    if !canonical_existing_ancestor.starts_with(target_root_canonical) {
        return Err(LpmError::Registry(format!(
            "path containment violation: '{}' resolves outside target '{}'",
            dest.display(),
            target_root_canonical.display()
        )));
    }

    Ok(dest)
}

/// mkdir + post-mkdir re-canonicalize phase of [`resolve_safe_dest`].
///
/// Must be called only after [`resolve_safe_dest_validate`] has passed
/// for the dest path that owns this `parent`. Splitting these phases
/// lets the `lpm add` Step-8 snapshot see every validated dest path
/// before any directory side effects happen — so a rollback restores
/// only files that legitimately needed to land under the target, not
/// anything created by an unvalidated path probe.
fn prepare_safe_dest_parent(
    parent: &Path,
    target_root_canonical: &Path,
) -> Result<PathBuf, LpmError> {
    // Step 5: Containment proven — NOW it's safe to create the parent.
    std::fs::create_dir_all(parent).map_err(|e| {
        LpmError::Registry(format!(
            "could not create destination parent '{}': {e}",
            parent.display()
        ))
    })?;

    // Step 6: Post-mkdir re-canonicalize. If a TOCTOU race swapped in a
    // symlink between Step 4 and Step 5, this surfaces it.
    let parent_canonical = parent.canonicalize().map_err(|e| {
        LpmError::Registry(format!(
            "could not canonicalize destination parent '{}': {e}",
            parent.display()
        ))
    })?;
    if !parent_canonical.starts_with(target_root_canonical) {
        return Err(LpmError::Registry(format!(
            "path containment violation post-create: '{}' resolves outside target '{}'",
            parent.display(),
            target_root_canonical.display()
        )));
    }

    Ok(parent_canonical)
}

// ---------------------------------------------------------------------------
// Interactive target directory detection
// ---------------------------------------------------------------------------

/// Detect a reasonable default install directory based on project framework.
///
/// Mirrors the JS CLI's `detectFramework()` + `getDefaultPath()`:
///   - Next.js (app router): `components/` if it exists, else `src/components`
///   - Next.js (pages router): `src/components`
///   - Vite / Remix: `src/components`
///   - Unknown: `components/` if it exists, else `src/components` if `src/` exists
fn detect_default_install_dir(project_dir: &Path, _ecosystem: &str) -> PathBuf {
    let framework = detect_framework(project_dir);

    match framework.as_str() {
        "next-app" => {
            // Next.js app router: components/ if it exists, else src/components
            if project_dir.join("components").is_dir() {
                project_dir.join("components")
            } else {
                project_dir.join("src/components")
            }
        }
        "next-pages" | "vite" | "remix" => project_dir.join("src/components"),
        _ => {
            // Generic: check existing directories
            if project_dir.join("src/components").is_dir() {
                project_dir.join("src/components")
            } else if project_dir.join("components").is_dir() {
                project_dir.join("components")
            } else if project_dir.join("src").is_dir() {
                project_dir.join("src/components")
            } else {
                project_dir.join("components")
            }
        }
    }
}

/// Detect the JS framework from package.json dependencies.
///
/// Returns: "next-app", "next-pages", "vite", "remix", or "unknown".
fn detect_framework(project_dir: &Path) -> String {
    let pkg_json_path = project_dir.join("package.json");
    let doc = match std::fs::read_to_string(&pkg_json_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
    {
        Some(d) => d,
        None => return "unknown".to_string(),
    };

    let has_dep = |name: &str| -> bool {
        doc.get("dependencies").and_then(|d| d.get(name)).is_some()
            || doc
                .get("devDependencies")
                .and_then(|d| d.get(name))
                .is_some()
    };

    if has_dep("next") {
        // Distinguish app router from pages router
        if project_dir.join("app").is_dir() {
            return "next-app".to_string();
        }
        return "next-pages".to_string();
    }

    if has_dep("@remix-run/react") {
        return "remix".to_string();
    }

    if has_dep("vite") {
        return "vite".to_string();
    }

    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// File conflict resolution with diff preview
// ---------------------------------------------------------------------------

/// Handle a file conflict when the destination already exists.
///
/// Compares content and prompts the user with diff preview when interactive.
fn handle_file_conflict(
    _source_path: &Path,
    target_path: &Path,
    new_content: Option<&str>,
    force: bool,
    yes: bool,
    json_output: bool,
) -> Result<ConflictAction, LpmError> {
    if force {
        return Ok(ConflictAction::Overwrite);
    }

    // Read existing content
    let existing_bytes = std::fs::read(target_path)?;

    // Compare: if new_content is Some, compare as text; otherwise compare bytes
    if let Some(new_text) = new_content {
        let existing_text = String::from_utf8_lossy(&existing_bytes);
        if existing_text.as_ref() == new_text {
            return Ok(ConflictAction::Skip); // Identical
        }
    }

    // Non-interactive: skip conflicts
    if yes || json_output || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(ConflictAction::Skip);
    }

    // Show diff preview
    let rel_display = target_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| target_path.display().to_string());

    eprintln!("\n  {} File exists: {}", "\u{26a0}".yellow(), rel_display);

    // Show a brief line-count diff summary
    if let Some(new_text) = new_content {
        let existing_text = String::from_utf8_lossy(&existing_bytes);
        let old_lines: Vec<&str> = existing_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();

        let mut added = 0usize;
        let mut removed = 0usize;
        let max_compare = old_lines.len().max(new_lines.len());
        for i in 0..max_compare {
            let old_line = old_lines.get(i).copied();
            let new_line = new_lines.get(i).copied();
            if old_line != new_line {
                if old_line.is_some() {
                    removed += 1;
                }
                if new_line.is_some() {
                    added += 1;
                }
            }
        }
        eprintln!(
            "    {} lines added, {} lines removed",
            format!("+{added}").green(),
            format!("-{removed}").red()
        );
    }

    let action: &str = cliclack::select("How to handle?")
        .item("skip", "Skip (keep existing)", "")
        .item("overwrite", "Overwrite", "")
        .item("diff", "View full diff", "")
        .initial_value("skip")
        .interact()
        .map_err(prompt_err)?;

    match action {
        "skip" => Ok(ConflictAction::Skip),
        "overwrite" => Ok(ConflictAction::Overwrite),
        "diff" => {
            // Print full diff then re-prompt
            if let Some(new_text) = new_content {
                let existing_text = String::from_utf8_lossy(&existing_bytes);
                eprintln!("\n  --- existing");
                eprintln!("  +++ incoming\n");
                for (i, (old, new)) in existing_text.lines().zip(new_text.lines()).enumerate() {
                    if old != new {
                        eprintln!("  {:>4} {} {}", i + 1, "-".red(), old.red());
                        eprintln!("  {:>4} {} {}", i + 1, "+".green(), new.green());
                    }
                }
                eprintln!();
            }

            // Re-prompt after showing diff
            let re_action: &str = cliclack::select("How to handle?")
                .item("skip", "Skip (keep existing)", "")
                .item("overwrite", "Overwrite", "")
                .initial_value("skip")
                .interact()
                .map_err(prompt_err)?;

            match re_action {
                "overwrite" => Ok(ConflictAction::Overwrite),
                _ => Ok(ConflictAction::Skip),
            }
        }
        _ => Ok(ConflictAction::Skip),
    }
}

// ---------------------------------------------------------------------------
// Dry-run mode
// ---------------------------------------------------------------------------

/// Show what would happen without writing any files.
#[allow(clippy::too_many_arguments)]
fn handle_dry_run(
    project_dir: &Path,
    target_dir: &Path,
    files: &[(String, String)],
    force: bool,
    add_target: &AddTarget,
    version: &str,
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    _ecosystem: &str,
    extract_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut file_actions = Vec::new();

    for (_src_rel, dest_rel) in files {
        let dest_target = target_dir.join(dest_rel);
        let exists = dest_target.exists();
        let action = if exists {
            if force { "overwrite" } else { "skip" }
        } else {
            "create"
        };
        file_actions.push((dest_rel.clone(), action));
    }

    // Count dependencies that would be installed
    let dep_count = count_dependencies(lpm_config, inline_config, extract_dir)?;

    if json_output {
        let files_json: Vec<serde_json::Value> = file_actions
            .iter()
            .map(|(path, action)| {
                serde_json::json!({
                    "path": path,
                    "action": action,
                })
            })
            .collect();

        let json = serde_json::json!({
            "success": true,
            "dry_run": true,
            "package": add_target.json_name(),
            "version": version,
            "target": target_dir.strip_prefix(project_dir).unwrap_or(target_dir).display().to_string(),
            "files": files_json,
            "dependencies_count": dep_count,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        eprintln!("\n  Dry run -- no files will be modified.\n");
        eprintln!(
            "  Would install to: {}",
            target_dir
                .strip_prefix(project_dir)
                .unwrap_or(target_dir)
                .display()
        );
        eprintln!("  Files:");
        for (path, action) in &file_actions {
            let icon = if *action == "create" {
                "+".green().to_string()
            } else if *action == "overwrite" {
                "~".yellow().to_string()
            } else {
                "-".dimmed().to_string()
            };
            eprintln!("    {} {} ({})", icon, path, action);
        }
        if dep_count > 0 {
            eprintln!("\n  Dependencies to install: {dep_count}");

            // Show individual dep names if available
            if let Some(config) = lpm_config
                && let Some(dep_config) = config.get("dependencies").and_then(|d| d.as_object())
            {
                for (config_key, dep_map) in dep_config {
                    let config_value = inline_config
                        .get(config_key)
                        .map(|s| s.as_str())
                        .unwrap_or("");
                    if config_value.is_empty() {
                        continue;
                    }
                    if let Some(deps) = dep_map.get(config_value).and_then(|d| d.as_array()) {
                        for dep in deps {
                            if let Some(dep_name) = dep.as_str() {
                                eprintln!("    {dep_name}");
                            }
                        }
                    }
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Package manager detection (for --pm=auto)
// ---------------------------------------------------------------------------

/// Detect the package manager from lockfile presence in the project directory.
fn detect_package_manager(project_dir: &Path) -> String {
    if project_dir.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if project_dir.join("yarn.lock").exists() {
        "yarn"
    } else if project_dir.join("bun.lockb").exists() || project_dir.join("bun.lock").exists() {
        "bun"
    } else if project_dir.join("package-lock.json").exists() {
        "npm"
    } else {
        "lpm"
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Dependency counting (for dry-run and --no-install-deps)
// ---------------------------------------------------------------------------

/// Collect every dependency the source package would install into the
/// consumer's `package.json`, in stable insertion order with duplicates
/// removed.
///
/// Mirrors the install path in [`handle_dependencies`]:
///
/// 1. Walk `lpm.config.json#dependencies` (config-conditional map),
///    selecting deps for each `inline_config` value. Comma-separated
///    multi-select values fan out across all selections.
/// 2. If step 1 produced nothing, fall back to the package's own
///    `package.json#dependencies + peerDependencies`. This is the
///    legacy path for source packages that ship a plain `package.json`
///    rather than a config-driven manifest.
///
/// `@lpm.dev/*` entries flow through unchanged: source-package deps
/// install identically regardless of whether they resolve through npm,
/// a private registry, or lpm.dev. Auth and access checks happen when
/// the selected package manager (`--pm`) runs its install step; we
/// don't pre-filter here.
///
/// Used by both [`handle_dependencies`] (the actual installer) and
/// [`count_dependencies`] (the dry-run / `--no-install-deps` UX) so the
/// preview, the skip-count message, and the install all walk the same
/// list. Without this shared spine, a config-aware package whose
/// `lpm.config.json#dependencies` was empty but whose `package.json`
/// carried real deps would silently disagree across the three surfaces.
fn collect_source_pkg_deps(
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    extract_dir: &Path,
) -> Result<Vec<(String, crate::save_spec::UserSaveIntent)>, LpmError> {
    // Authoring contract: declaring `dependencies` in `lpm.config.json` —
    // even with conditional branches that produce zero matches for a
    // given consumer config — opts out of the legacy `package.json`
    // fallback. Mirrors how `files[]` works: declared = source of truth.
    // Without this rule, a consumer who picks a config that doesn't
    // match any conditional branch would silently pull every entry
    // from the package's own `package.json#dependencies`, which the
    // author almost certainly didn't intend.
    let dep_config_present = lpm_config
        .as_ref()
        .and_then(|c| c.get("dependencies"))
        .is_some();

    // Each entry is parsed once into `(name, intent)`. Dedup is by parsed
    // `name`, not the raw entry string — so `["react", "react@^18"]` in
    // the same conditional collapses to a single entry (first-wins, per
    // Phase 33's "explicit user input wins" rule, which here means the
    // first declaration the author wrote).
    let mut deps: Vec<(String, crate::save_spec::UserSaveIntent)> = Vec::new();
    let push_if_new = |deps: &mut Vec<(String, crate::save_spec::UserSaveIntent)>,
                       raw: &str|
     -> Result<(), LpmError> {
        let (name, intent) = crate::save_spec::parse_user_save_intent(raw)?;
        if !deps.iter().any(|(existing, _)| existing == &name) {
            deps.push((name, intent));
        }
        Ok(())
    };

    // 1. Conditional deps from `lpm.config.json#dependencies`.
    if let Some(config) = lpm_config
        && let Some(dep_config) = config.get("dependencies").and_then(|d| d.as_object())
    {
        for (config_key, dep_map) in dep_config {
            let config_value = inline_config
                .get(config_key)
                .map(|s| s.as_str())
                .unwrap_or("");
            if config_value.is_empty() {
                continue;
            }

            let selected_values: Vec<&str> = if config_value.contains(',') {
                config_value.split(',').map(|v| v.trim()).collect()
            } else {
                vec![config_value]
            };

            for value in &selected_values {
                if let Some(arr) = dep_map.get(*value).and_then(|d| d.as_array()) {
                    for dep in arr {
                        if let Some(raw) = dep.as_str() {
                            push_if_new(&mut deps, raw)?;
                        }
                    }
                }
            }
        }
    }

    // 2. Legacy fallback: package's own `package.json` deps + peerDeps.
    //    Fires only when `lpm.config.json#dependencies` is absent
    //    entirely. A declared-but-unmatched `dependencies` block is a
    //    deliberate "no deps for this configuration" signal from the
    //    author, not a request to fall back.
    //
    //    The package's `package.json` already carries explicit version
    //    ranges per the npm spec (`{"react": "^18"}`). Reconstruct each
    //    entry as `name@range` and push it through the same parser so
    //    the downstream save-spec logic preserves it verbatim.
    if !dep_config_present {
        let pkg_json_path = extract_dir.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_json_path)
            && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content)
        {
            for section in ["dependencies", "peerDependencies"] {
                if let Some(map) = doc.get(section).and_then(|d| d.as_object()) {
                    for (name, version) in map {
                        let raw = match version.as_str() {
                            Some(v) if !v.is_empty() => format!("{name}@{v}"),
                            _ => name.clone(),
                        };
                        push_if_new(&mut deps, &raw)?;
                    }
                }
            }
        }
    }

    Ok(deps)
}

/// Count how many dependencies would be installed without actually installing them.
///
/// Returns `collect_source_pkg_deps(...).len()` so dry-run preview and
/// `--no-install-deps` skip-count agree with the install path.
fn count_dependencies(
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    extract_dir: &Path,
) -> Result<usize, LpmError> {
    Ok(collect_source_pkg_deps(lpm_config, inline_config, extract_dir)?.len())
}

/// Phase 64 #9.4 preflight: refuse to copy a deps-declaring source
/// package into a project with no `package.json`.
///
/// Without a manifest, the dep entries the source declares have
/// nowhere to land — the user would end up with copied source files
/// importing packages they can't install. Block the run before any
/// side effect with a remediation hint pointing at `lpm init` /
/// `npm init -y`.
///
/// Gates (must all hold to fire):
/// - `!no_install_deps`: the user explicitly opting out of dep
///   install acknowledges they'll handle it themselves; respect that.
/// - `lpm_config.is_some()`: simple-path tarballs (no
///   `lpm.config.json`) intentionally skip auto-install; the
///   bare-imports notice at Step 9.1 surfaces what the user needs.
/// - `!project_dir/package.json exists`: the actual blocking
///   condition — no manifest to mutate.
/// - `collect_source_pkg_deps(...).len() > 0`: a deps-free source
///   package (just files, no imports) is safe to land in a no-
///   manifest project.
fn preflight_no_manifest_with_deps(
    project_dir: &Path,
    extract_dir: &Path,
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    no_install_deps: bool,
) -> Result<(), LpmError> {
    if no_install_deps {
        return Ok(());
    }
    if lpm_config.is_none() {
        return Ok(());
    }
    if project_dir.join("package.json").exists() {
        return Ok(());
    }
    if collect_source_pkg_deps(lpm_config, inline_config, extract_dir)?.is_empty() {
        return Ok(());
    }

    Err(LpmError::Script(
        "this source package declares dependencies, but the project has no \
         `package.json` to record them in.\n\n  \
         Run `lpm init` (or `npm init -y`) first to create a manifest, \
         then re-run `lpm add`.\n\n  \
         To copy the source files without installing the declared dependencies, \
         pass `--no-install-deps` and resolve the imports yourself."
            .to_string(),
    ))
}

/// Detect the buyer's import alias from tsconfig.json or jsconfig.json.
///
/// Reads `compilerOptions.paths` and returns the first alias ending with `/*`.
/// e.g., `{ "@/*": ["./src/*"] }` -> `"@/"`
fn detect_buyer_alias(project_dir: &Path) -> Option<String> {
    for config_name in ["tsconfig.json", "jsconfig.json"] {
        let path = project_dir.join(config_name);
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        // Strip comments (// and /* */) for JSON parsing
        let stripped = strip_json_comments(&content);
        let config: serde_json::Value = serde_json::from_str(&stripped).ok()?;
        let paths = config
            .get("compilerOptions")
            .and_then(|co| co.get("paths"))
            .and_then(|p| p.as_object())?;

        for key in paths.keys() {
            if key.ends_with("/*") {
                // "@/*" -> "@/"
                return Some(key[..key.len() - 1].to_string());
            }
        }
    }
    None
}

/// Strip single-line (//) and block (/* */) comments from JSON-like content.
fn strip_json_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;

    while let Some(c) = chars.next() {
        if in_string {
            result.push(c);
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    result.push(next);
                    chars.next();
                }
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            result.push(c);
        } else if c == '/' {
            match chars.peek() {
                Some('/') => {
                    // Skip until end of line
                    for ch in chars.by_ref() {
                        if ch == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next(); // consume *
                    while let Some(ch) = chars.next() {
                        if ch == '*' && chars.peek() == Some(&'/') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => result.push(c),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Read lpm.config.json from extracted package.
fn read_lpm_config(extract_dir: &Path) -> Option<serde_json::Value> {
    let path = extract_dir.join("lpm.config.json");
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Coerce a JSON value from `lpm.config.json` to its canonical string
/// form for the inline-config map.
///
/// `inline_config` stores every field value as a string (booleans are
/// `"true"` / `"false"`, numbers stringified) so the downstream
/// substitution + condition-eval paths can treat all values uniformly.
/// This helper mirrors that contract.
///
/// Accepts the natural authored form (`true`, `42`) AND the legacy
/// stringified form (`"true"`, `"42"`) for back-compat with packages
/// whose `lpm.config.json` was authored against the older string-only
/// reader. Returns `None` for nulls / arrays / objects, which aren't
/// valid leaf values in this surface.
fn json_value_to_config_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Determine target directory for file installation.
fn resolve_target_dir(
    project_dir: &Path,
    explicit_path: Option<&str>,
    ecosystem: &str,
    swift_target: Option<&str>,
) -> Result<PathBuf, LpmError> {
    if let Some(path) = explicit_path {
        return Ok(project_dir.join(path));
    }

    match ecosystem {
        "swift" => {
            let xcode_exists = std::fs::read_dir(project_dir)
                .map(|entries| {
                    entries.flatten().any(|e| {
                        e.path()
                            .extension()
                            .map(|ext| ext == "xcodeproj" || ext == "xcworkspace")
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            if xcode_exists {
                // Swift Xcode: Packages/LPMComponents/Sources/{target}
                let mut path = project_dir
                    .join("Packages")
                    .join("LPMComponents")
                    .join("Sources");
                if let Some(t) = swift_target {
                    path = path.join(t);
                }
                Ok(path)
            } else {
                // SPM project: Sources/{target}
                let mut path = project_dir.join("Sources");
                if let Some(t) = swift_target {
                    path = path.join(t);
                }
                Ok(path)
            }
        }
        _ => {
            // JS: detect framework for smart defaults
            Ok(detect_default_install_dir(project_dir, ecosystem))
        }
    }
}

/// Filter files using lpm.config.json `files` array with condition evaluation.
fn filter_config_files(
    extract_dir: &Path,
    files_rules: &[serde_json::Value],
    config: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, LpmError> {
    let provided_params: HashSet<&str> = config.keys().map(|k| k.as_str()).collect();
    let mut result = Vec::new();

    for rule in files_rules {
        let src_pattern = rule.get("src").and_then(|v| v.as_str()).unwrap_or("");
        let dest = rule
            .get("dest")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let include = rule
            .get("include")
            .and_then(|v| v.as_str())
            .unwrap_or("always");

        // Evaluate condition
        match include {
            "never" => continue,
            "when" => {
                if let Some(condition) = rule.get("condition").and_then(|c| c.as_object()) {
                    let mut matches = true;
                    for (key, expected) in condition {
                        // If the key wasn't explicitly provided, include the file (all-by-default)
                        if !provided_params.contains(key.as_str()) {
                            continue;
                        }
                        // Coerce native JSON values (`true`, `42`) to
                        // their canonical string form so authors can use
                        // the natural authored type. Falls back to "" for
                        // null/array/object — same semantics as the
                        // legacy string-only path.
                        let expected_str =
                            json_value_to_config_string(expected).unwrap_or_default();
                        let actual = config.get(key).map(|s| s.as_str()).unwrap_or("");

                        // Support comma-separated multi-select
                        let actual_values: Vec<&str> = actual.split(',').collect();
                        if !actual_values.contains(&expected_str.as_str()) {
                            matches = false;
                            break;
                        }
                    }
                    if !matches {
                        continue;
                    }
                }
            }
            _ => {} // "always" or missing -- include
        }

        // Expand src pattern to actual file paths
        let expanded = expand_src_pattern(extract_dir, src_pattern);

        // Compute the base directory of the src pattern (strip trailing /** or /*)
        let pattern_base = src_pattern.trim_end_matches("/**").trim_end_matches("/*");

        let multi_file = expanded.len() > 1;
        for path in expanded {
            if !path.is_file() {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(extract_dir) {
                let src_rel = rel.to_string_lossy().to_string();
                let dest_rel = if let Some(d) = &dest {
                    if d.ends_with('/') {
                        format!(
                            "{}{}",
                            d,
                            rel.file_name().unwrap_or_default().to_string_lossy()
                        )
                    } else if multi_file {
                        // Multiple files: maintain structure relative to glob base
                        // JS CLI: path.relative(baseSrc, srcFile) then path.join(dest, relFromBase)
                        let base_path = extract_dir.join(pattern_base);
                        let rel_from_base = path.strip_prefix(&base_path).unwrap_or(rel);
                        format!(
                            "{}/{}",
                            d.trim_end_matches('/'),
                            rel_from_base.to_string_lossy()
                        )
                    } else {
                        d.clone()
                    }
                } else {
                    src_rel.clone()
                };
                result.push((src_rel, dest_rel));
            }
        }
    }

    Ok(result)
}

/// Expand a src pattern from lpm.config.json to actual file paths.
///
/// Matches the JS CLI's `expandSrcGlob` behaviour:
///   - Exact paths: `"lib/utils.js"` → check existence
///   - Recursive wildcard: `"components/dialog/**"` → walk directory tree
///   - Single-dir wildcard: `"styles/*.css"` → regex match in one directory
///
/// The `glob` crate's `**` only matches directories, NOT files, so we must
/// handle `/**` ourselves with a recursive walk (same as the JS CLI does).
fn expand_src_pattern(extract_dir: &Path, pattern: &str) -> Vec<PathBuf> {
    // No wildcard → exact path check
    if !pattern.contains('*') {
        let full_path = extract_dir.join(pattern);
        if full_path.exists() {
            return vec![full_path];
        }
        return vec![];
    }

    // Recursive wildcard: "dir/**"
    if let Some(base) = pattern.strip_suffix("/**") {
        // strip "/**"
        let base_dir = extract_dir.join(base);
        if !base_dir.is_dir() {
            return vec![];
        }
        let mut results = Vec::new();
        collect_files_recursive(&base_dir, &mut results);
        return results;
    }

    // Single-directory wildcard: "dir/*.ext" or "*.md"
    let last_slash = pattern.rfind('/');
    let (dir_part, file_part) = match last_slash {
        Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
        None => (".", pattern),
    };

    if file_part.contains('*') {
        let full_dir = if dir_part == "." {
            extract_dir.to_path_buf()
        } else {
            extract_dir.join(dir_part)
        };
        if !full_dir.is_dir() {
            return vec![];
        }

        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&full_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && glob_simple_match(file_part, name)
                {
                    results.push(path);
                }
            }
        }
        return results;
    }

    // Fallback: treat as exact path
    let full_path = extract_dir.join(pattern);
    if full_path.exists() {
        vec![full_path]
    } else {
        vec![]
    }
}

/// Match a filename against a simple glob pattern (supports `*` only).
///
/// Examples: `"*.css"` matches `"style.css"`, `"*.*"` matches `"foo.bar"`.
fn glob_simple_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Split pattern on '*' and check that all parts appear in order
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return pattern == name;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First part must be a prefix
            if !name.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Last part must be a suffix
            if !name[pos..].ends_with(part) {
                return false;
            }
            pos = name.len();
        } else {
            match name[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Recursively collect all files in a directory.
fn collect_files_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, results);
        } else if path.is_file() {
            results.push(path);
        }
    }
}

/// Collect source files, checking package.json#lpm.source first (legacy fallback),
/// then falling back to all files in the extraction directory.
fn collect_source_with_fallback(extract_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    // Check package.json for lpm.source field (legacy packages)
    let pkg_json_path = extract_dir.join("package.json");
    if pkg_json_path.exists()
        && let Ok(content) = std::fs::read_to_string(&pkg_json_path)
        && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(source_dir) = doc
            .get("lpm")
            .and_then(|l| l.get("source"))
            .and_then(|s| s.as_str())
    {
        let source_path = extract_dir.join(source_dir);
        if source_path.is_dir() {
            let mut files = Vec::new();
            collect_dir_no_skip(&source_path, &source_path, &mut files)?;
            if !files.is_empty() {
                return Ok(files);
            }
        } else if source_path.is_file() {
            // Single file source
            let name = source_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            return Ok(vec![(name.clone(), name)]);
        }
    }

    // Fall back to collecting all source files
    collect_all_source_files(extract_dir)
}

/// Collect files from a directory without the node_modules/test skip list.
/// Used for lpm.source directories where we want everything.
fn collect_dir_no_skip(
    dir: &Path,
    root: &Path,
    files: &mut Vec<(String, String)>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir_no_skip(&path, root, files)?;
        } else if path.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            let rel_str = rel.to_string_lossy().to_string();
            files.push((rel_str.clone(), rel_str));
        }
    }
    Ok(())
}

/// Collect all files from extracted package (fallback when no config).
fn collect_all_source_files(extract_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    let mut files = Vec::new();
    collect_dir(extract_dir, extract_dir, &mut files)?;
    Ok(files)
}

fn collect_dir(dir: &Path, root: &Path, files: &mut Vec<(String, String)>) -> Result<(), LpmError> {
    static SKIP: &[&str] = &["node_modules", ".git", "__tests__", "test", "tests"];

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if SKIP.contains(&name_str.as_ref()) {
                continue;
            }
            collect_dir(&path, root, files)?;
        } else if path.is_file() {
            if name_str == "package.json" || name_str == "lpm.config.json" {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().to_string();
                files.push((rel_str.clone(), rel_str));
            }
        }
    }
    Ok(())
}

/// Compute the version spec to write into the consumer's `package.json`
/// for each collected source-package dependency.
///
/// Pure function over already-resolved metadata so it can be unit-tested
/// without spinning up a registry client. The orchestration (network
/// fetch, intent collection) lives in `handle_dependencies`.
///
/// Author-controlled specs (`Exact` / `Range` / `Wildcard` / `Workspace`)
/// short-circuit through [`crate::save_spec::decide_saved_dependency_spec`]
/// without touching `resolved_latest`. Bare names and dist-tags require
/// a resolved `Version` — missing entries fail fast with a remediation
/// hint pointing at explicit-version pinning or `lpm login`.
fn build_save_decisions(
    entries: &[(String, crate::save_spec::UserSaveIntent)],
    resolved_latest: &HashMap<String, lpm_semver::Version>,
    save_config: crate::save_spec::SaveConfig,
) -> Result<Vec<(String, String)>, LpmError> {
    // Sentinel never read for Tier-1 intents (Wildcard/Workspace/Exact/
    // Range short-circuit before `decide_saved_dependency_spec` touches
    // `resolved`). Using a real-but-fake Version keeps the function
    // signature simple — alternative is a duplicate split in this loop.
    let sentinel = lpm_semver::Version::parse("0.0.0").expect("0.0.0 is a valid Version");

    let mut out = Vec::with_capacity(entries.len());
    for (name, intent) in entries {
        let resolved = match intent {
            crate::save_spec::UserSaveIntent::Bare
            | crate::save_spec::UserSaveIntent::DistTag(_) => {
                resolved_latest.get(name).ok_or_else(|| {
                    LpmError::Registry(format!(
                        "could not resolve a version for source-package dependency '{name}'. \
                         The package may not exist in the configured registry, or your auth \
                         may not grant access. Pin an explicit version in the source package's \
                         lpm.config.json#dependencies (e.g., \"{name}@^1.0\"), or run `lpm login` \
                         if it's an @lpm.dev/* dep."
                    ))
                })?
            }
            _ => &sentinel,
        };
        let decision = crate::save_spec::decide_saved_dependency_spec(
            intent,
            resolved,
            crate::save_spec::SaveFlags::default(),
            save_config,
        )?;
        out.push((name.clone(), decision.spec_to_write));
    }
    Ok(out)
}

/// Handle npm/LPM dependencies from lpm.config.json.
///
/// Source-package deps install identically regardless of registry origin
/// — npm, private, or `@lpm.dev/*` all flow through `package.json` ➜
/// install via the selected package manager (`--pm`). Auth and access
/// checks happen at the install step, not here.
///
/// Save-spec policy mirrors `lpm install`:
/// - Author-provided ranges (`"react@^18"`, `"lodash@4.17.21"`) are
///   preserved verbatim.
/// - Bare names (`"react"`) and dist-tags (`"react@latest"`) resolve
///   against the registry; the resolved version flows into the
///   user's project save-policy default — typically `^resolvedLatest`,
///   or whatever `~/.lpm/config.toml > save-prefix|save-exact` says.
/// - Resolution is **per-package routed** through `RouteTable` so
///   `.npmrc`-declared private registries, the LPM Worker, and the
///   public npm registry all work for bare/dist-tag entries. Mirrors
///   the resolver walker's three-arm dispatch
///   ([`lpm_resolver::walker`] Phase 58 day-4).
/// - Resolution **fails the whole call** before mutating
///   `package.json`. Without this fail-fast posture, a stuck resolve
///   would leave the manifest with stranded entries that the trailing
///   install can't recover.
///
/// **Rollback ownership lives at the caller** ([`run`]). The
/// `ManifestTransaction` snapshot now opens BEFORE Step 8 (file copy)
/// so a Step 8 / Step 9 / Step 9.1 failure rolls back source files
/// alongside the manifest + lockfiles. This function therefore does
/// not own a tx of its own — every error path returns `Err`, which
/// the caller's `?` propagates and the caller's tx Drops.
///
/// `effective_pm` is pre-resolved at the call site (handles
/// `--pm auto`) so this function picks dispatch arms by exact match
/// without re-running detection.
#[allow(clippy::too_many_arguments)]
async fn handle_dependencies(
    client: &RegistryClient,
    route_table: &lpm_registry::RouteTable,
    project_dir: &Path,
    extract_dir: &Path,
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    ecosystem: &str,
    _yes: bool,
    json_output: bool,
    effective_pm: &str,
) -> Result<usize, LpmError> {
    let entries = collect_source_pkg_deps(lpm_config, inline_config, extract_dir)?;

    if entries.is_empty() {
        return Ok(0);
    }

    if !json_output {
        output::info(&format!("Installing {} dependencies...", entries.len()));
    }

    // Resolve latest version for each Bare / DistTag entry up-front,
    // dispatching per-package through `RouteTable`. The walker's
    // three-arm pattern (LPM batch / npm fan-out / custom registries)
    // is overkill for the typical < 10 source-package deps; serial
    // routed fetches are simpler and the bound is small enough that
    // wall time is dominated by network setup, not parallelism.
    let mut resolved: HashMap<String, lpm_semver::Version> = HashMap::new();
    for (name, intent) in &entries {
        let tag = match intent {
            crate::save_spec::UserSaveIntent::DistTag(t) => t.as_str(),
            crate::save_spec::UserSaveIntent::Bare => "latest",
            _ => continue,
        };

        // `@lpm.dev/*` packages take the LPM-direct metadata route —
        // same call the source package itself uses at the top of
        // `add::run`. Everything else (npm-published, private-
        // registry-declared via .npmrc) goes through
        // `get_npm_metadata_routed`, which dispatches by the route
        // table to the correct upstream.
        let pkg_meta = if name.starts_with("@lpm.dev/") {
            let pkg = PackageName::parse(name).map_err(|e| {
                LpmError::Registry(format!("invalid @lpm.dev/* dep name '{name}': {e}"))
            })?;
            client.get_package_metadata(&pkg).await.map_err(|e| {
                LpmError::Registry(format!(
                    "could not resolve '{name}' against lpm.dev: {e}. \
                     Pin an explicit version (e.g., \"{name}@^1.0\") in the source \
                     package's lpm.config.json#dependencies, or run `lpm login` to \
                     authenticate."
                ))
            })?
        } else {
            let route = route_table.route_for_package(name);
            client
                .get_npm_metadata_routed(name, route)
                .await
                .map_err(|e| {
                    LpmError::Registry(format!(
                        "could not resolve '{name}' against the registry: {e}. \
                         Either the package doesn't exist there or your auth \
                         doesn't grant access. Pin an explicit version \
                         (e.g., \"{name}@^1.0\") in the source package's \
                         lpm.config.json#dependencies."
                    ))
                })?
        };
        let resolved_version_str = pkg_meta.resolve_version_spec(tag).map_err(|e| {
            LpmError::Registry(format!("resolving '{name}@{tag}' against registry: {e}"))
        })?;
        let version = lpm_semver::Version::parse(&resolved_version_str).map_err(|e| {
            LpmError::Registry(format!(
                "registry returned non-semver version '{resolved_version_str}' for '{name}': {e}"
            ))
        })?;
        resolved.insert(name.clone(), version);
    }

    // Build the (name, spec_to_write) list using the shared save-spec
    // decision helper. Honors `~/.lpm/config.toml` + `./lpm.toml` save
    // policy — same precedence chain `lpm install <pkg>` uses.
    let save_config = crate::save_config::SaveConfigLoader::load_for_project(project_dir)?;
    let decisions = build_save_decisions(&entries, &resolved, save_config)?;

    let pkg_json_path = project_dir.join("package.json");

    // No `package.json` ⇒ no manifest to mutate. The caller's tx
    // already snapshotted the manifest as `optional` (records `None`
    // for missing files), so this early-return is purely the user-
    // facing warning surface. Tracked separately at phase64 #9.4 as a
    // UX finding (hard-error vs auto-init) — out of scope here.
    if !pkg_json_path.exists() {
        output::warn(
            "no package.json found -- dependencies not installed. Run `lpm install` manually.",
        );
        let _ = ecosystem;
        return Ok(entries.len());
    }

    // Mutate `package.json` with the resolved specs. The caller's
    // [`ManifestTransaction`] owns the rollback boundary — any `?`
    // error from here on propagates up and the caller's `tx` drops
    // without `commit()`, restoring every snapshotted path (manifest,
    // LPM lockfiles, the selected PM's lockfile, every Step-8 dest
    // file) and invalidating `.lpm/install-hash`.
    {
        let content = std::fs::read_to_string(&pkg_json_path)
            .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
        let mut doc: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| LpmError::Registry(format!("failed to parse package.json: {e}")))?;

        let deps = doc.as_object_mut().and_then(|o| {
            o.entry("dependencies")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        });

        if let Some(deps) = deps {
            for (name, spec) in &decisions {
                // Phase 33 "do not rewrite existing entries on bare
                // reinstall" semantics: if the consumer already pinned
                // a range for this dep, we keep theirs.
                deps.entry(name.clone())
                    .or_insert_with(|| serde_json::Value::String(spec.clone()));
            }
        }

        let updated = serde_json::to_string_pretty(&doc)
            .map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;
        std::fs::write(&pkg_json_path, format!("{updated}\n"))
            .map_err(|e| LpmError::Registry(format!("failed to write package.json: {e}")))?;
    }

    // Dispatch to the selected package manager. EVERY failure path
    // returns `Err`, which drops the caller's tx and rolls back the
    // manifest + lockfiles + dest files + invalidates
    // `.lpm/install-hash`. The pre-fix code used `output::warn` and
    // silently continued; that's exactly what left users with a
    // half-applied manifest the trailing install never finished
    // filling in.
    match effective_pm {
        "lpm" => {
            // Phase 35 Step 6 fix: use the injected client. Pre-fix
            // this site built a fresh `RegistryClient::new()` with
            // no token attached, so any post-add `lpm install` for
            // an `@lpm.dev` package would have hit anonymous /
            // failed. The injected client carries `--registry` and
            // the shared `SessionManager`.
            crate::commands::install::run_with_options(
                client,
                project_dir,
                json_output,
                false,                                                 // offline
                false,                                                 // force
                false,                                                 // allow_new
                false, // strict_integrity (Phase 59.0 F5)
                None,  // linker_override
                false, // no_skills
                false, // no_editor_setup
                true,  // no_security_summary
                false, // auto_build
                None,  // target_set: shadcn-style add never targets multiple workspace members
                None, // direct_versions_out: shadcn-style add does not finalize Phase 33 placeholders
                None, // script_policy_override: `lpm add` does not expose policy flags
                None, // advisor_override: `lpm add` does not expose `--advisor`
                None, // min_release_age_override: shadcn-style add uses the chain
                crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm add` does not expose drift-override flags
                // Phase 46.1 rework: `lpm add` does not surface its
                // own sandbox-mode flags. The env / config / default
                // chain inside `rebuild::run` still applies.
                false, // strict_sandbox
                false, // no_sandbox
            )
            .await
            .map_err(|e| {
                LpmError::Script(format!(
                    "lpm install failed: {e}. package.json + lockfiles rolled back to pre-add state."
                ))
            })?;
        }
        pm_name @ ("npm" | "pnpm" | "yarn" | "bun") => {
            if !json_output {
                output::info(&format!("Running {pm_name} install..."));
            }
            let status = std::process::Command::new(pm_name)
                .arg("install")
                .current_dir(project_dir)
                .status()
                .map_err(|e| {
                    LpmError::Script(format!(
                        "{pm_name} install failed to spawn: {e}. \
                         package.json + lockfile rolled back to pre-add state."
                    ))
                })?;
            if !status.success() {
                return Err(LpmError::Script(format!(
                    "{pm_name} install exited with non-zero status. \
                     package.json + lockfile rolled back to pre-add state."
                )));
            }
        }
        other => {
            return Err(LpmError::Script(format!(
                "unknown package manager: {other}. Use: lpm, npm, pnpm, yarn, bun, auto"
            )));
        }
    }

    // Trailing install succeeded — return Ok and let the caller commit
    // the wider tx after Step 9.1.
    let _ = ecosystem; // Ecosystem used for future per-ecosystem dep handling

    Ok(entries.len())
}

/// Lockfile paths to snapshot for the selected package manager.
///
/// Returns the per-PM lockfile(s) so a partial install — the install
/// step that fails after writing a partial lockfile — gets rolled back
/// alongside `package.json`. Without this, rolling back the manifest
/// alone would leave a manifest/lockfile split-brain on `--pm npm`,
/// `--pm pnpm`, `--pm yarn`, or `--pm bun`.
///
/// Returns an empty vec for `lpm` (its lockfiles `lpm.lock` and
/// `lpm.lockb` are already snapshotted by the caller) and for unknown
/// values (the dispatch arm errors on those before any tx mutation).
fn pm_lockfile_paths(pm: &str, project_dir: &Path) -> Vec<PathBuf> {
    match pm {
        "npm" => vec![project_dir.join("package-lock.json")],
        "pnpm" => vec![project_dir.join("pnpm-lock.yaml")],
        "yarn" => vec![project_dir.join("yarn.lock")],
        // bun ships both binary (`.lockb`, default) and text (`.lock`,
        // newer) formats depending on version. Snapshot both as
        // optional so whichever bun writes is rolled back; the absent
        // one's snapshot records `None` and is a no-op on rollback.
        "bun" => vec![project_dir.join("bun.lock"), project_dir.join("bun.lockb")],
        _ => Vec::new(),
    }
}

/// For Swift packages: recursively install LPM dependencies.
#[allow(clippy::too_many_arguments)]
async fn handle_swift_lpm_deps(
    client: &RegistryClient,
    project_dir: &Path,
    ver_meta: &lpm_registry::VersionMetadata,
    yes: bool,
    json_output: bool,
    force: bool,
    dry_run: bool,
    no_install_deps: bool,
    no_skills: bool,
    no_editor_setup: bool,
    pm: &str,
) -> Result<(), LpmError> {
    // Check versionMeta for swift manifest dependencies
    // These are in the version's metadata, not in lpm.config.json
    let deps = &ver_meta.dependencies;
    if deps.is_empty() {
        return Ok(());
    }

    // Filter to LPM deps only
    let lpm_deps: Vec<(&String, &String)> = deps
        .iter()
        .filter(|(name, _)| name.starts_with("@lpm.dev/"))
        .collect();

    if lpm_deps.is_empty() {
        return Ok(());
    }

    if !json_output {
        output::info(&format!(
            "This package has {} LPM dependencies -- installing recursively",
            lpm_deps.len()
        ));
    }

    for (dep_name, dep_range) in &lpm_deps {
        if !json_output {
            output::info(&format!("  Adding dependency: {dep_name}@{dep_range}"));
        }
        // Recursive add (source delivery for recursive deps)
        Box::pin(run(
            client,
            project_dir,
            dep_name,
            None,
            yes,
            json_output,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            pm,
            None,
            None,
        ))
        .await?;
    }

    Ok(())
}

/// Print security warnings for a single package version.
pub fn print_security_warnings(
    name: &str,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
) {
    let mut warnings: Vec<String> = Vec::new();

    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("info");
            let desc = finding
                .description
                .as_deref()
                .unwrap_or("security concern detected");
            warnings.push(format!("[{}] {}", severity, desc));
        }
    }

    if let Some(tags) = &ver_meta.behavioral_tags {
        let mut dangerous = Vec::new();
        if tags.eval {
            dangerous.push("eval()");
        }
        if tags.child_process {
            dangerous.push("child_process");
        }
        if tags.shell {
            dangerous.push("shell exec");
        }
        if tags.dynamic_require {
            dangerous.push("dynamic require");
        }
        if !dangerous.is_empty() {
            warnings.push(format!("uses {}", dangerous.join(", ")));
        }
    }

    if let Some(scripts) = &ver_meta.lifecycle_scripts {
        let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        if !script_names.is_empty() {
            warnings.push(format!(
                "has lifecycle scripts: {}",
                script_names.join(", ")
            ));
        }
    }

    if warnings.is_empty() {
        return;
    }

    println!();
    output::warn(&format!(
        "{} ({}) has {} issue(s):",
        name.bold(),
        version,
        warnings.len()
    ));
    for warning in &warnings {
        println!("    {} {}", "\u{26a0}".yellow(), warning);
    }
    println!("  Run {} for details", "lpm audit".bold());
}

/// Typosquatting warning returned when a package name is suspiciously similar to a popular package.
struct TyposquatWarning {
    /// The bare name the user typed.
    input: String,
    /// The popular package it's similar to.
    similar: String,
}

/// Check if a package name should trigger a typosquatting warning.
///
/// Returns `None` (no warning) if:
/// - The name is an exact match for a popular package
/// - The name is not similar to any popular package
/// - The exact package name is already present in the lockfile (user accepted it before)
/// - The lockfile doesn't exist or can't be read (fail-open: skip lockfile check, still warn)
fn should_warn_typosquatting(pkg_ref: &str, project_dir: &Path) -> Option<TyposquatWarning> {
    let bare_name = pkg_ref.strip_prefix("@lpm.dev/").unwrap_or(pkg_ref);

    // If the name is in the lockfile, the user has already accepted it — skip the warning.
    let in_lockfile =
        lpm_lockfile::Lockfile::read_fast(&project_dir.join(lpm_lockfile::LOCKFILE_NAME))
            .map(|lf| lf.packages.iter().any(|p| p.name == pkg_ref))
            .unwrap_or(false);

    if in_lockfile {
        return None;
    }

    lpm_security::typosquatting::check_typosquatting(bare_name).map(|similar| TyposquatWarning {
        input: bare_name.to_string(),
        similar: similar.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a minimal lockfile with the given package names.
    fn write_lockfile(dir: &Path, package_names: &[&str]) {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for name in package_names {
            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                dependencies: Vec::new(),
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            });
        }
        let path = dir.join(lpm_lockfile::LOCKFILE_NAME);
        let toml = toml::to_string_pretty(&lockfile).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
    }

    #[test]
    fn typosquatting_warns_when_not_in_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        // No lockfile — "loadash" should warn (similar to "lodash")
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(result.is_some(), "should warn when no lockfile exists");
        assert_eq!(result.unwrap().similar, "lodash");
    }

    #[test]
    fn typosquatting_warns_when_lockfile_exists_but_package_absent() {
        let dir = tempfile::tempdir().unwrap();
        write_lockfile(dir.path(), &["react", "express"]);
        // "loadash" is NOT in lockfile — should warn
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(result.is_some(), "should warn when package not in lockfile");
        assert_eq!(result.unwrap().similar, "lodash");
    }

    #[test]
    fn typosquatting_skips_when_package_in_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        // "loadash" is IN the lockfile — the user has accepted it, no warning
        write_lockfile(dir.path(), &["loadash"]);
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(
            result.is_none(),
            "should NOT warn when package is in lockfile"
        );
    }

    #[test]
    fn typosquatting_skips_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        // "lodash" is an exact match — not a typosquat
        let result = should_warn_typosquatting("lodash", dir.path());
        assert!(result.is_none(), "exact match should not warn");
    }

    #[test]
    fn typosquatting_lockfile_skip_works_for_scoped_packages() {
        let dir = tempfile::tempdir().unwrap();
        // Scoped LPM package in lockfile
        write_lockfile(dir.path(), &["@lpm.dev/owner.loadash"]);
        let result = should_warn_typosquatting("@lpm.dev/owner.loadash", dir.path());
        assert!(
            result.is_none(),
            "scoped package in lockfile should not warn"
        );
    }

    #[test]
    fn typosquatting_lockfile_skip_does_not_cross_match() {
        let dir = tempfile::tempdir().unwrap();
        // "lodash" is in lockfile but "loadash" is NOT — should still warn
        write_lockfile(dir.path(), &["lodash"]);
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(
            result.is_some(),
            "different package name should still warn even if lockfile has the real one"
        );
    }

    // ── resolve_add_target — Phase 60.0.a + 60.0.b ──────────────────

    #[test]
    fn resolve_add_target_lpm_full_scoped() {
        let (target, version, _config) =
            resolve_add_target("@lpm.dev/tolga.sample-source-code1").unwrap();
        match target {
            AddTarget::Lpm(pkg) => {
                assert_eq!(pkg.scoped(), "@lpm.dev/tolga.sample-source-code1");
            }
            AddTarget::Npm { spec } => panic!("expected Lpm variant, got Npm({spec})"),
        }
        assert!(version.is_none());
    }

    #[test]
    fn resolve_add_target_lpm_with_version_and_inline_config() {
        let (target, version, config) =
            resolve_add_target("@lpm.dev/acme.design@2.1.0?component=dialog&styling=panda")
                .unwrap();
        match &target {
            AddTarget::Lpm(pkg) => assert_eq!(pkg.scoped(), "@lpm.dev/acme.design"),
            AddTarget::Npm { .. } => panic!("expected Lpm variant"),
        }
        assert_eq!(version.as_deref(), Some("2.1.0"));
        assert_eq!(config.get("component").map(String::as_str), Some("dialog"));
        assert_eq!(config.get("styling").map(String::as_str), Some("panda"));
    }

    #[test]
    fn resolve_add_target_npm_bare() {
        let (target, version, _config) = resolve_add_target("react").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(pkg) => panic!("expected Npm, got Lpm({})", pkg.scoped()),
        }
        assert!(version.is_none());
    }

    #[test]
    fn resolve_add_target_npm_scoped() {
        let (target, _, _) = resolve_add_target("@juggle/resize-observer").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "@juggle/resize-observer"),
            AddTarget::Lpm(pkg) => panic!("expected Npm, got Lpm({})", pkg.scoped()),
        }
    }

    #[test]
    fn resolve_add_target_npm_with_version() {
        let (target, version, _) = resolve_add_target("react@18.3.1").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(_) => panic!("expected Npm"),
        }
        assert_eq!(version.as_deref(), Some("18.3.1"));
    }

    #[test]
    fn resolve_add_target_npm_with_dist_tag() {
        let (target, version, _) = resolve_add_target("react@beta").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(_) => panic!("expected Npm"),
        }
        assert_eq!(version.as_deref(), Some("beta"));
    }

    /// Phase 60.0.b regression — dotted bare names like `lodash.merge`,
    /// `lodash.debounce`, `lodash.throttle` are real npm packages and
    /// MUST resolve to `AddTarget::Npm` verbatim. Pre-Phase-60 they
    /// were silently rewritten to `@lpm.dev/lodash.merge` (which doesn't
    /// exist on lpm.dev) — see CLAUDE.md "Naming model (firm rule)".
    #[test]
    fn resolve_add_target_dotted_npm_name_is_npm_not_lpm_shorthand() {
        for spec in [
            "lodash.merge",
            "lodash.debounce",
            "lodash.throttle",
            "tolga.foo",
        ] {
            let (target, _, _) = resolve_add_target(spec).unwrap();
            match target {
                AddTarget::Npm { spec: s } => assert_eq!(s, spec),
                AddTarget::Lpm(pkg) => panic!(
                    "'{spec}' must resolve to Npm, not Lpm({}) — auto-prepend regression",
                    pkg.scoped()
                ),
            }
        }
    }

    #[test]
    fn resolve_add_target_npm_with_inline_config() {
        let (target, _, config) = resolve_add_target("react?theme=dark&variant=primary").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(_) => panic!("expected Npm"),
        }
        assert_eq!(config.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(config.get("variant").map(String::as_str), Some("primary"));
    }

    #[test]
    fn resolve_add_target_empty_input_errors() {
        let err = resolve_add_target("").unwrap_err();
        match err {
            LpmError::InvalidPackageName(_) => {}
            other => panic!("expected InvalidPackageName, got {other:?}"),
        }
    }

    #[test]
    fn add_target_display_renders_lpm_scoped() {
        let (target, _, _) = resolve_add_target("@lpm.dev/owner.pkg").unwrap();
        assert_eq!(target.display(), "@lpm.dev/owner.pkg");
    }

    #[test]
    fn add_target_display_renders_npm_verbatim() {
        let (target, _, _) = resolve_add_target("@juggle/resize-observer").unwrap();
        assert_eq!(target.display(), "@juggle/resize-observer");

        let (target, _, _) = resolve_add_target("lodash.merge").unwrap();
        assert_eq!(target.display(), "lodash.merge");
    }

    // ── resolve_safe_dest — Phase 60.0.f / D6 ───────────────────────

    #[test]
    fn resolve_safe_dest_normal_path_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        let resolved = resolve_safe_dest(&canonical, target, "components/foo.tsx").unwrap();
        assert!(resolved.starts_with(&canonical));
        assert!(resolved.ends_with("foo.tsx"));
    }

    #[test]
    fn resolve_safe_dest_dotdot_in_path_rejected_with_no_external_dir_created() {
        // Phase 60 audit regression — the pre-fix implementation rejected
        // the path with a containment error BUT left a stray
        // `target_dir/../escaped/` directory created on disk because
        // `create_dir_all(parent)` ran before the containment check.
        // Reject up-front via lexical `..` ban; assert no directory was
        // ever created outside the target.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest(&canonical, &target, "../../escaped/evil.txt")
            .expect_err("should reject");
        match err {
            LpmError::Registry(msg) => {
                assert!(
                    msg.contains("'..'") || msg.contains("parent-directory"),
                    "expected lexical `..` reject, got: {msg}"
                );
            }
            other => panic!("expected Registry error, got {other:?}"),
        }

        // CRITICAL: no directory created outside target_dir.
        let escaped_within_project = outer.path().join("project").join("escaped");
        assert!(
            !escaped_within_project.exists(),
            "containment failure: '{}' was created as a side-effect before the error fired",
            escaped_within_project.display(),
        );
        let canonical_outer = outer.path().canonicalize().unwrap();
        for entry in std::fs::read_dir(&canonical_outer).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert_eq!(
                name, "project",
                "containment failure: unexpected entry '{name}' in outer tempdir",
            );
        }
    }

    #[test]
    fn resolve_safe_dest_absolute_dest_rejected_with_no_external_dir_created() {
        // Phase 60 audit regression — `target_dir.join(absolute)` returns
        // the absolute path verbatim (`Path::join` semantics), so an
        // absolute `dest_rel` would route the write to whatever path the
        // tarball asked for. Pre-fix, `create_dir_all` ran before the
        // containment check, leaving the external directory created.
        // The lexical absolute-path reject must fire BEFORE any mkdir.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        // Use a deterministic external path inside an UNRELATED tempdir
        // so the test cannot accidentally observe the test harness's
        // own scratch directory.
        let elsewhere =
            std::env::temp_dir().join(format!("lpm-phase60-abs-dest-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&elsewhere);
        let abs_dest = elsewhere.join("evil.txt");
        let abs_dest_str = abs_dest.to_string_lossy().to_string();

        let err = resolve_safe_dest(&canonical, &target, &abs_dest_str)
            .expect_err("should reject absolute dest");
        match err {
            LpmError::Registry(msg) => {
                assert!(
                    msg.contains("absolute"),
                    "expected lexical absolute-path reject, got: {msg}"
                );
            }
            other => panic!("expected Registry error, got {other:?}"),
        }

        // CRITICAL: external directory NOT created.
        assert!(
            !elsewhere.exists(),
            "containment failure: absolute-dest mkdir leaked outside target — '{}' was created",
            elsewhere.display(),
        );
    }

    #[test]
    fn resolve_safe_dest_dotdot_in_middle_of_path_also_rejected() {
        // `foo/../bar.txt` lexically resolves back inside target, but we
        // still reject it: legitimate package authors don't need
        // parent-references in their dest paths, and accepting them
        // would force a more complex lexical-resolution path that's
        // easier to get wrong than a blanket reject.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest(&canonical, &target, "foo/../bar.txt")
            .expect_err("should reject `..` in middle");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("'..'") || msg.contains("parent-directory"),
                "expected lexical `..` reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
        // No `foo/` created inside target.
        assert!(
            !target.join("foo").exists(),
            "containment failure: even a benign-looking `foo/../bar.txt` should not mkdir `foo/`"
        );
    }

    #[test]
    fn resolve_safe_dest_existing_symlink_destination_rejected() {
        // Pre-create target_dir/foo as a symlink to /tmp/elsewhere
        // and confirm resolve_safe_dest refuses to write through it.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let target = dir.path();
            let canonical = target.canonicalize().unwrap();
            let symlink_path = target.join("foo");
            std::os::unix::fs::symlink(elsewhere.path(), &symlink_path).unwrap();

            let err = resolve_safe_dest(&canonical, target, "foo").expect_err("should reject");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("symlink"),
                    "expected symlink-refusal error, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_safe_dest_intermediate_symlink_dir_rejected() {
        // target/foo/ is a symlink to /tmp/elsewhere. Writing `foo/bar.txt`
        // would resolve to `/tmp/elsewhere/bar.txt` — outside the target
        // root. The canonical-parent check must catch this.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let target = dir.path();
            let canonical = target.canonicalize().unwrap();
            let symlink_dir = target.join("foo");
            std::os::unix::fs::symlink(elsewhere.path(), &symlink_dir).unwrap();

            let err =
                resolve_safe_dest(&canonical, target, "foo/bar.txt").expect_err("should reject");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("path containment violation"),
                    "expected containment error, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    // ── resolve_safe_dest_validate — pure validation (Phase 64 #9.3) ──
    //
    // The validate phase is the half of `resolve_safe_dest` that has
    // NO directory side effects. `lpm add`'s rollback flow opens a
    // `ManifestTransaction` snapshot between validation and the
    // mkdir-during-copy step, so validate must reject every malicious
    // dest_rel without creating ancestor directories. Otherwise a
    // failed `lpm add` would leave empty directories under the
    // target that the rollback can't reach.

    #[test]
    fn resolve_safe_dest_validate_does_not_mkdir_on_success() {
        // Happy path. `dest_rel` points inside an existing target dir;
        // validate must NOT create the `components/` parent that the
        // copy step would later need. That mkdir belongs in the
        // separate prepare phase.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        let dest_path =
            resolve_safe_dest_validate(&canonical, target, "components/foo.tsx").unwrap();
        assert_eq!(dest_path, target.join("components/foo.tsx"));
        assert!(
            !target.join("components").exists(),
            "validate must not create ancestor directories"
        );
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_dotdot_without_mkdir() {
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest_validate(&canonical, &target, "../../escaped/evil.txt")
            .expect_err("should reject");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("'..'") || msg.contains("parent-directory"),
                "expected `..` reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
        assert!(
            !outer.path().join("escaped").exists(),
            "validate must not create directories outside target"
        );
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_absolute_without_mkdir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        // Build an absolute path that lives outside the target.
        let scratch = tempfile::tempdir().unwrap();
        let abs_dest = scratch.path().join("evil.txt");
        let abs_dest_str = abs_dest.to_string_lossy();

        let err = resolve_safe_dest_validate(&canonical, target, &abs_dest_str)
            .expect_err("should reject absolute path");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("absolute"),
                "expected absolute reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
    }

    #[test]
    fn step_8_write_path_pins_canonical_parent_through_intermediate_symlink() {
        // Phase 64 #9.3 second-pass-audit regression: production
        // Step 8 used to call `prepare_safe_dest_parent` and discard
        // its return value, then write to the pre-canonicalize
        // `dest_path`. That re-opened the post-mkdir TOCTOU window
        // — a symlink swap between the canonicalize check and the
        // write would route the write through the new symlink.
        //
        // The fix composes the final dest path from the
        // canonicalized parent: `parent_canonical.join(file_name)`.
        // This test reproduces the symlinked-intermediate-parent
        // case (inside target, so validation passes) and asserts
        // that the composed path follows the canonical resolution
        // — i.e., points at the real underlying directory, not the
        // symlinked alias.
        #[cfg(unix)]
        {
            let outer = tempfile::tempdir().unwrap();
            let target = outer.path().join("project").join("components");
            let real_dir = target.join("real");
            std::fs::create_dir_all(&real_dir).unwrap();
            // Create a symlinked alias INSIDE target pointing at real_dir.
            std::os::unix::fs::symlink(&real_dir, target.join("aliased")).unwrap();
            let target_root_canonical = target.canonicalize().unwrap();

            // Validate the path through the symlinked alias. Validation
            // passes because the canonical ancestor (real_dir) lives
            // inside target_root_canonical.
            let validated =
                resolve_safe_dest_validate(&target_root_canonical, &target, "aliased/foo.tsx")
                    .expect("validation should pass for symlink-inside-target");
            // Pre-canonicalize path runs through `aliased/`.
            assert!(
                validated.to_string_lossy().contains("aliased"),
                "validate returns the pre-canonicalize path, got {validated:?}"
            );

            // Prepare phase canonicalizes the parent. Returns the
            // CANONICAL parent — production composes the final dest
            // from this, not from the pre-canonicalize value.
            let parent_canonical =
                prepare_safe_dest_parent(validated.parent().unwrap(), &target_root_canonical)
                    .unwrap();
            let file_name = validated.file_name().unwrap();
            let final_dest = parent_canonical.join(file_name);

            // Production must write through the canonical resolution
            // (`real/foo.tsx`), NOT through the alias (`aliased/foo.tsx`).
            // The pre-fix bug used the alias path and re-introduced the
            // TOCTOU write-through-symlink risk.
            let canonical_target = real_dir.canonicalize().unwrap();
            assert_eq!(
                final_dest,
                canonical_target.join("foo.tsx"),
                "final dest must be canonical-pinned, got {final_dest:?}"
            );
            assert!(
                !final_dest.to_string_lossy().contains("aliased"),
                "final dest must not retain the symlinked-alias name, got {final_dest:?}"
            );
        }
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_dest_that_is_existing_symlink_without_mkdir() {
        // The dest path itself already resolves through a symlink.
        // Validate must reject before mkdir touches the parent chain.
        #[cfg(unix)]
        {
            let outer = tempfile::tempdir().unwrap();
            let target = outer.path().join("target");
            std::fs::create_dir_all(&target).unwrap();
            let canonical = target.canonicalize().unwrap();
            let outside = outer.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();

            // Create a symlink at `<target>/dest.tsx` → `<outside>`.
            std::os::unix::fs::symlink(&outside, target.join("dest.tsx")).unwrap();

            let err = resolve_safe_dest_validate(&canonical, &target, "dest.tsx")
                .expect_err("should reject existing symlink at dest");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("symlink"),
                    "expected symlink reject, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    // ── lpm.config.json value coercion (json_value_to_config_string) ───
    //
    // The wire contract for `lpm.config.json` accepts both the natural
    // authored form (JSON booleans, numbers) AND the legacy stringified
    // form (`"true"`, `"42"`). The schema published at
    // `https://lpm.dev/schemas/lpm.config.json` declares booleans
    // natively, so the runtime MUST accept both forms or the schema and
    // the runtime would disagree on whether `"default": true` is valid.
    //
    // These tests pin the contract at the helper level so a regression
    // in any of the three call sites (interactive prompt default, --yes
    // required-field default, files[].condition value) gets caught.

    mod config_value_coercion {
        use super::super::*;
        use serde_json::json;

        #[test]
        fn native_boolean_true_to_string() {
            assert_eq!(
                json_value_to_config_string(&json!(true)),
                Some("true".into())
            );
        }

        #[test]
        fn native_boolean_false_to_string() {
            assert_eq!(
                json_value_to_config_string(&json!(false)),
                Some("false".into())
            );
        }

        #[test]
        fn legacy_string_true_passes_through() {
            // Back-compat: packages authored against the older
            // string-only reader continue to work. `"true"` (quoted)
            // and `true` (bare) must produce identical inline-config
            // values.
            assert_eq!(
                json_value_to_config_string(&json!("true")),
                Some("true".into())
            );
        }

        #[test]
        fn legacy_string_false_passes_through() {
            assert_eq!(
                json_value_to_config_string(&json!("false")),
                Some("false".into())
            );
        }

        #[test]
        fn integer_to_string() {
            // Numeric defaults (e.g., `"default": 42` for a port) get
            // stringified — same shape as inline-config values.
            assert_eq!(json_value_to_config_string(&json!(42)), Some("42".into()));
        }

        #[test]
        fn arbitrary_string_passes_through() {
            assert_eq!(
                json_value_to_config_string(&json!("dialog")),
                Some("dialog".into())
            );
        }

        #[test]
        fn null_returns_none() {
            assert_eq!(json_value_to_config_string(&json!(null)), None);
        }

        #[test]
        fn array_returns_none() {
            // Arrays aren't valid leaf values in this surface — a
            // multi-select default uses a comma-joined string per
            // existing convention.
            assert_eq!(json_value_to_config_string(&json!(["a", "b"])), None);
        }

        #[test]
        fn object_returns_none() {
            assert_eq!(json_value_to_config_string(&json!({"x": 1})), None);
        }
    }

    // ── filter_config_files: condition-eval coercion regression ──────
    //
    // Pins the third bug site: `condition` map values must accept both
    // native JSON booleans AND legacy string forms. Pre-fix the
    // condition-eval read `expected.as_str().unwrap_or("")`, so a
    // `condition: {includeTests: true}` silently became `""` and never
    // matched the inline-config value `"true"`.

    mod filter_config_files_condition {
        use super::super::*;
        use serde_json::json;
        use std::collections::HashMap;

        fn make_extract_dir() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            // Create a few files so src patterns resolve.
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/index.ts"), "// index").unwrap();
            std::fs::write(dir.path().join("src/test.ts"), "// test").unwrap();
            dir
        }

        fn config(pairs: &[(&str, &str)]) -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        }

        #[test]
        fn native_boolean_condition_true_matches_string_true() {
            // Author writes `"condition": {"withTests": true}` (native
            // JSON bool). User opted in, so inline_config has
            // "withTests" → "true". Rule must match → file included.
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": true},
            })];
            let out =
                filter_config_files(dir.path(), &rules, &config(&[("withTests", "true")])).unwrap();
            assert_eq!(out.len(), 1, "native-bool condition must match: {out:?}");
        }

        #[test]
        fn native_boolean_condition_true_excludes_string_false() {
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": true},
            })];
            let out = filter_config_files(dir.path(), &rules, &config(&[("withTests", "false")]))
                .unwrap();
            assert!(out.is_empty(), "must exclude on opposite value: {out:?}");
        }

        #[test]
        fn legacy_string_condition_still_matches() {
            // Back-compat: packages authored against the older
            // string-only reader continue to work.
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": "true"},
            })];
            let out =
                filter_config_files(dir.path(), &rules, &config(&[("withTests", "true")])).unwrap();
            assert_eq!(out.len(), 1, "legacy string condition must match: {out:?}");
        }

        #[test]
        fn condition_skipped_when_param_not_provided() {
            // Pre-existing "all-by-default" semantic: if the user didn't
            // supply the param at all, the file is included. This test
            // pins that contract isn't broken by the coercion fix.
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": true},
            })];
            let out = filter_config_files(dir.path(), &rules, &HashMap::new()).unwrap();
            assert_eq!(
                out.len(),
                1,
                "missing param must include the file (all-by-default): {out:?}",
            );
        }
    }

    // -----------------------------------------------------------------
    // Source-package dependency collection (Phase 64 finding #9)
    //
    // Source packages can declare deps from any registry — npm, private,
    // or `@lpm.dev/*`. The collector must NOT pre-filter by name; auth
    // and access checks happen when the selected package manager (`--pm`)
    // runs its install step.
    // -----------------------------------------------------------------

    mod source_pkg_deps {
        use super::*;
        use crate::save_spec::UserSaveIntent;

        fn write_pkg_json(dir: &Path, body: serde_json::Value) {
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&body).unwrap(),
            )
            .unwrap();
        }

        /// Project name strings out of a `(name, intent)` collection so
        /// the older "did this package end up in the result" assertions
        /// stay readable after the Tier-2 refactor.
        fn names(deps: &[(String, UserSaveIntent)]) -> Vec<String> {
            deps.iter().map(|(n, _)| n.clone()).collect()
        }

        #[test]
        fn config_json_path_collects_lpm_dev_and_npm_deps_together() {
            // A source package declares a mix of registries under the
            // same conditional. All three must survive to the install
            // step — the collector is registry-agnostic by contract.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": [
                            "lucide-react",
                            "@lpm.dev/owner.icon-helpers",
                            "@private-scope/icon-utils",
                        ]
                    }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();
            let names = names(&deps);

            assert!(
                names.contains(&"lucide-react".to_string()),
                "npm-published deps must flow through: {names:?}"
            );
            assert!(
                names.contains(&"@lpm.dev/owner.icon-helpers".to_string()),
                "@lpm.dev/* deps must flow through (regression: pre-fix they were silently dropped): {names:?}"
            );
            assert!(
                names.contains(&"@private-scope/icon-utils".to_string()),
                "private-registry-style names must flow through: {names:?}"
            );
            assert_eq!(deps.len(), 3, "no duplicates introduced: {names:?}");

            // Bare names (no `@version`) should land as `Bare` intent —
            // the helper that consumes this list resolves bare entries
            // against the registry to write `^resolvedLatest`, while
            // explicit ranges short-circuit verbatim.
            for (_, intent) in &deps {
                assert!(
                    matches!(intent, UserSaveIntent::Bare),
                    "bare entries must classify as Bare, got {intent:?}"
                );
            }
        }

        #[test]
        fn config_json_preserves_author_provided_version_ranges() {
            // Authors who pin a specific range get it preserved verbatim
            // through to package.json — no resolve, no caret default.
            // Mirrors `lpm install zod@^4.3.0` semantics from Phase 33.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": [
                            "lucide-react@^0.400.0",   // Range
                            "@lpm.dev/owner.tools@1.2.3", // Exact
                            "react@latest",            // DistTag
                            "lodash@*",                // explicit Wildcard
                        ]
                    }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();
            assert_eq!(deps.len(), 4, "{deps:?}");

            let by_name: HashMap<String, UserSaveIntent> = deps.into_iter().collect();
            assert_eq!(
                by_name.get("lucide-react"),
                Some(&UserSaveIntent::Range("^0.400.0".to_string())),
            );
            assert_eq!(
                by_name.get("@lpm.dev/owner.tools"),
                Some(&UserSaveIntent::Exact("1.2.3".to_string())),
            );
            assert_eq!(
                by_name.get("react"),
                Some(&UserSaveIntent::DistTag("latest".to_string())),
            );
            assert_eq!(by_name.get("lodash"), Some(&UserSaveIntent::Wildcard));
        }

        #[test]
        fn dedup_is_by_name_first_entry_wins() {
            // Author writes the same package twice with different
            // intents — say a pinned range under one conditional and a
            // bare name under another. First-write-wins keeps the more
            // restrictive declaration when the order is "specific then
            // general," matching how authors typically read top-down.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "ui": {
                        "minimal": ["react@^18.2.0", "react"]
                    }
                }
            });
            let inline = HashMap::from([("ui".to_string(), "minimal".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();

            assert_eq!(deps.len(), 1, "duplicates collapse: {deps:?}");
            assert_eq!(
                deps[0],
                (
                    "react".to_string(),
                    UserSaveIntent::Range("^18.2.0".to_string())
                ),
                "first declaration's intent wins"
            );
        }

        #[test]
        fn legacy_package_json_fallback_collects_lpm_dev_and_npm_deps_together() {
            // When `lpm.config.json#dependencies` is absent or its
            // conditionals don't match, the collector falls back to
            // the package's own `package.json#dependencies` +
            // `peerDependencies`. The same registry-agnostic rule
            // applies: every name flows through, and the package.json
            // version range is preserved as the intent (so the trailing
            // install writes that exact range, not `*`).
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "name": "source-pkg",
                    "version": "1.0.0",
                    "dependencies": {
                        "react": "^18",
                        "@lpm.dev/owner.runtime": "^1",
                    },
                    "peerDependencies": {
                        "@private-scope/peer-shim": "^2",
                    }
                }),
            );

            let deps = collect_source_pkg_deps(&None, &HashMap::new(), extract.path()).unwrap();
            let by_name: HashMap<String, UserSaveIntent> = deps.iter().cloned().collect();

            assert_eq!(
                by_name.get("react"),
                Some(&UserSaveIntent::Range("^18".to_string())),
                "package.json version range must be preserved as the intent"
            );
            assert_eq!(
                by_name.get("@lpm.dev/owner.runtime"),
                Some(&UserSaveIntent::Range("^1".to_string())),
                "@lpm.dev/* in legacy fallback must flow through with its declared range"
            );
            assert_eq!(
                by_name.get("@private-scope/peer-shim"),
                Some(&UserSaveIntent::Range("^2".to_string())),
                "peerDependencies must flow through with their declared range"
            );
            assert_eq!(deps.len(), 3, "{deps:?}");
        }

        #[test]
        fn legacy_fallback_does_not_fire_when_config_json_yielded_deps() {
            // Once `lpm.config.json#dependencies` produces any deps,
            // the legacy fallback is skipped. Without this, a config-
            // json package would also pull in its own package.json
            // deps, doubling up.
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": { "should-not-appear": "*" }
                }),
            );

            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();

            assert_eq!(names(&deps), vec!["lucide-react".to_string()]);
            assert!(
                !names(&deps).contains(&"should-not-appear".to_string()),
                "legacy fallback must not fire when config-json produced deps: {deps:?}"
            );
        }

        #[test]
        fn legacy_fallback_does_not_fire_when_dependencies_field_present_but_unmatched() {
            // Author contract: declaring `dependencies` in
            // `lpm.config.json` — even with conditional branches that
            // don't match the consumer's selected config — opts out of
            // the legacy package.json fallback. The author's empty/
            // unmatched signal IS the answer ("no deps for this
            // config"), not a cue to silently fall back.
            //
            // Pre-tightening, the gate was `deps.is_empty()` which
            // fired the fallback whenever no conditional matched —
            // contradicting the schema description and pulling
            // package.json deps the author didn't ask for.
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": {
                        "would-leak-without-gate": "*",
                        "@lpm.dev/owner.would-also-leak": "*",
                    }
                }),
            );

            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            // Consumer picks a value that doesn't match any inner key.
            let inline = HashMap::from([("icons".to_string(), "phosphor".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();

            assert!(
                deps.is_empty(),
                "declared `dependencies` with no matching conditional must yield zero deps, NOT trigger the legacy fallback: {deps:?}"
            );
        }

        #[test]
        fn legacy_fallback_fires_only_when_dependencies_field_absent() {
            // The fallback IS the right answer when `lpm.config.json`
            // ships without a `dependencies` field — the author hasn't
            // declared a config-driven contract, so we read the
            // package's own `package.json` deps as the source of truth.
            // Tests both shapes: lpm_config = None (no config file) and
            // lpm_config = Some(...) without a `dependencies` key.
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": { "react": "^18" }
                }),
            );

            // Shape A: no lpm.config.json at all.
            let deps_a = collect_source_pkg_deps(&None, &HashMap::new(), extract.path()).unwrap();
            assert_eq!(names(&deps_a), vec!["react".to_string()]);
            assert_eq!(deps_a[0].1, UserSaveIntent::Range("^18".to_string()));

            // Shape B: lpm.config.json present but no `dependencies` field.
            let lpm_config_no_deps = serde_json::json!({
                "ecosystem": "js",
                "files": [{ "src": "src/**" }]
            });
            let deps_b =
                collect_source_pkg_deps(&Some(lpm_config_no_deps), &HashMap::new(), extract.path())
                    .unwrap();
            assert_eq!(names(&deps_b), vec!["react".to_string()]);
            assert_eq!(deps_b[0].1, UserSaveIntent::Range("^18".to_string()));
        }

        #[test]
        fn count_dependencies_agrees_with_collect() {
            // Preview / `--no-install-deps` skip-count must report the
            // same number the install path will actually install. The
            // pre-fix `count_dependencies` walked only `lpm.config.json`
            // and applied an `@lpm.dev/*` filter; both undercounts.
            let extract = tempfile::tempdir().unwrap();

            // Case A: config-json path, mixed registries.
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": ["lucide-react", "@lpm.dev/owner.helpers"]
                    }
                }
            });
            let inline_a = HashMap::from([("icons".to_string(), "lucide".to_string())]);
            let count_a =
                count_dependencies(&Some(lpm_config.clone()), &inline_a, extract.path()).unwrap();
            let collect_a = collect_source_pkg_deps(&Some(lpm_config), &inline_a, extract.path())
                .unwrap()
                .len();
            assert_eq!(count_a, collect_a, "count must agree with collect");
            assert_eq!(count_a, 2, "both @lpm.dev/* and npm names counted");

            // Case B: legacy-fallback path triggered (empty config-json
            // conditionals + populated package.json).
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": { "react": "*", "@lpm.dev/owner.runtime": "*" }
                }),
            );
            let count_b = count_dependencies(&None, &HashMap::new(), extract.path()).unwrap();
            let collect_b = collect_source_pkg_deps(&None, &HashMap::new(), extract.path())
                .unwrap()
                .len();
            assert_eq!(count_b, collect_b);
            assert_eq!(count_b, 2);
        }

        #[test]
        fn multi_select_values_fan_out_across_selections() {
            // Comma-separated multi-select values pull deps from each
            // matching inner key. Regression: the comma-split logic
            // must not drop names that happen to share any prefix.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": ["lucide-react"],
                        "heroicons": ["@heroicons/react"],
                    }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide,heroicons".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();
            let names = names(&deps);

            assert!(names.contains(&"lucide-react".to_string()));
            assert!(names.contains(&"@heroicons/react".to_string()));
            assert_eq!(deps.len(), 2);
        }

        // ───── build_save_decisions ────────────────────────────────────
        //
        // Decision-layer tests inject a fake `resolved_latest` so they
        // don't need a real registry. The collector → resolver →
        // build_save_decisions chain runs end-to-end in workflow tests;
        // here we exercise the policy logic in isolation.

        fn v(s: &str) -> lpm_semver::Version {
            lpm_semver::Version::parse(s).unwrap()
        }

        #[test]
        fn build_save_decisions_bare_name_gets_caret_resolved() {
            // The Phase 33 default: a bare name resolves to the latest
            // version and writes back as `^x.y.z`. This is the
            // user-visible improvement over the pre-fix `*` write.
            let entries = vec![("react".to_string(), UserSaveIntent::Bare)];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();

            assert_eq!(
                out,
                vec![("react".to_string(), "^18.3.1".to_string())],
                "bare name must resolve to caret range"
            );
        }

        #[test]
        fn build_save_decisions_explicit_range_preserved_verbatim() {
            // Author-pinned range short-circuits before any resolve —
            // we don't even consult `resolved_latest` for these intents.
            let entries = vec![(
                "react".to_string(),
                UserSaveIntent::Range("^18.0.0".to_string()),
            )];
            let resolved = HashMap::new(); // intentionally empty

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();

            assert_eq!(out, vec![("react".to_string(), "^18.0.0".to_string())]);
        }

        #[test]
        fn build_save_decisions_explicit_exact_preserved_verbatim() {
            let entries = vec![(
                "lodash".to_string(),
                UserSaveIntent::Exact("4.17.21".to_string()),
            )];
            let out = build_save_decisions(
                &entries,
                &HashMap::new(),
                crate::save_spec::SaveConfig::default(),
            )
            .unwrap();
            assert_eq!(out, vec![("lodash".to_string(), "4.17.21".to_string())]);
        }

        #[test]
        fn build_save_decisions_explicit_wildcard_preserved() {
            // The author asked for `*` — a deliberate "any version"
            // signal. Phase 33 preserves user wildcards verbatim.
            let entries = vec![("any-thing".to_string(), UserSaveIntent::Wildcard)];
            let out = build_save_decisions(
                &entries,
                &HashMap::new(),
                crate::save_spec::SaveConfig::default(),
            )
            .unwrap();
            assert_eq!(out, vec![("any-thing".to_string(), "*".to_string())]);
        }

        #[test]
        fn build_save_decisions_dist_tag_resolved_to_caret() {
            // `react@latest` and `react@beta` both resolve via the
            // registry (the helper expects the caller to have already
            // followed the tag → version indirection). Stable resolved
            // versions get the caret default; prereleases pin exact for
            // safety per Phase 33's Tier 3.
            let entries = vec![(
                "react".to_string(),
                UserSaveIntent::DistTag("latest".to_string()),
            )];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();
            assert_eq!(out, vec![("react".to_string(), "^18.3.1".to_string())]);
        }

        #[test]
        fn build_save_decisions_dist_tag_prerelease_pins_exact() {
            // Prerelease-exact safety: a `next` tag resolving to a
            // prerelease shouldn't auto-widen via caret. Without this,
            // installing `@latest` could later jump to a stable `^1.0`
            // and surprise the consumer with a major bump.
            let entries = vec![(
                "react".to_string(),
                UserSaveIntent::DistTag("next".to_string()),
            )];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("19.0.0-rc.1"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();
            assert_eq!(
                out,
                vec![("react".to_string(), "19.0.0-rc.1".to_string())],
                "prereleases pin exact, no caret widening"
            );
        }

        #[test]
        fn build_save_decisions_fails_fast_when_bare_unresolved() {
            // If the registry doesn't return a version for a bare entry
            // — package missing, auth blocked, network down — we MUST
            // fail before the caller mutates package.json. Otherwise
            // the consumer ends up with a stranded entry the trailing
            // install can't recover.
            let entries = vec![("nonexistent".to_string(), UserSaveIntent::Bare)];
            let resolved = HashMap::new();

            let err =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .expect_err("missing resolved version must error");

            let msg = format!("{err}");
            assert!(
                msg.contains("nonexistent"),
                "error must name the unresolvable package: {msg}"
            );
            assert!(
                msg.contains("Pin an explicit version") || msg.contains("@^1.0"),
                "error must hint at the explicit-version workaround: {msg}"
            );
        }

        #[test]
        fn build_save_decisions_honors_save_exact_config() {
            // User config `save-exact = true` (set in `~/.lpm/config.toml`)
            // applies to source-package deps the same way it applies to
            // `lpm install <pkg>` — bare entries write the exact version,
            // not a caret range.
            let entries = vec![("react".to_string(), UserSaveIntent::Bare)];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));

            let save_config = crate::save_spec::SaveConfig {
                save_exact: true,
                ..Default::default()
            };
            let out = build_save_decisions(&entries, &resolved, save_config).unwrap();

            assert_eq!(
                out,
                vec![("react".to_string(), "18.3.1".to_string())],
                "save-exact config writes exact, no prefix"
            );
        }

        #[test]
        fn build_save_decisions_mix_of_intents_in_one_pass() {
            // End-to-end: a single source package's collected entries
            // span every intent variant the author can produce. The
            // helper has to handle all four in one call.
            let entries = vec![
                ("react".to_string(), UserSaveIntent::Bare),
                (
                    "lucide-react".to_string(),
                    UserSaveIntent::Range("^0.400.0".to_string()),
                ),
                (
                    "lodash".to_string(),
                    UserSaveIntent::Exact("4.17.21".to_string()),
                ),
                (
                    "@lpm.dev/owner.tools".to_string(),
                    UserSaveIntent::DistTag("latest".to_string()),
                ),
            ];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));
            resolved.insert("@lpm.dev/owner.tools".to_string(), v("2.0.0"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();

            assert_eq!(
                out,
                vec![
                    ("react".to_string(), "^18.3.1".to_string()),
                    ("lucide-react".to_string(), "^0.400.0".to_string()),
                    ("lodash".to_string(), "4.17.21".to_string()),
                    ("@lpm.dev/owner.tools".to_string(), "^2.0.0".to_string()),
                ],
            );
        }

        // ── preflight_no_manifest_with_deps (Phase 64 #9.4) ───────────
        //
        // Hard-error before any side effects when a deps-declaring
        // source package would land in a project with no manifest.
        // Pre-fix, `lpm add` copied source files first and warned
        // late inside `handle_dependencies`; the preflight runs
        // before Step 7 prompts and Step 8 file copies.

        #[test]
        fn preflight_errors_when_config_json_declares_deps_and_no_manifest() {
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let err = preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &inline,
                false,
            )
            .expect_err("preflight must hard-error");

            let msg = format!("{err}");
            assert!(
                msg.contains("lpm init") || msg.contains("npm init"),
                "error must point at `lpm init` / `npm init -y`: {msg}"
            );
            assert!(
                msg.contains("no `package.json`") || msg.contains("no package.json"),
                "error must explain the missing manifest: {msg}"
            );
            assert!(
                msg.contains("--no-install-deps"),
                "error must surface the --no-install-deps escape hatch: {msg}"
            );
        }

        #[test]
        fn preflight_errors_when_legacy_package_json_fallback_yields_deps_and_no_consumer_manifest()
        {
            // The source ships an `lpm.config.json` without a
            // `dependencies` field but the package's own
            // `package.json` declares deps. The legacy fallback in
            // `collect_source_pkg_deps` picks those up; preflight
            // should still fire.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            std::fs::write(
                extract.path().join("package.json"),
                r#"{"name":"src-pkg","version":"1.0.0","dependencies":{"react":"^18"}}"#,
            )
            .unwrap();

            let lpm_config = serde_json::json!({ "ecosystem": "js", "files": [] });

            let err = preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &HashMap::new(),
                false,
            )
            .expect_err("preflight must catch legacy-fallback deps too");
            assert!(format!("{err}").contains("lpm init"));
        }

        #[test]
        fn preflight_passes_when_consumer_has_package_json() {
            let project = tempfile::tempdir().unwrap();
            std::fs::write(project.path().join("package.json"), "{}").unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &inline,
                false,
            )
            .expect("manifest exists, preflight must pass");
        }

        #[test]
        fn preflight_passes_when_source_declares_no_deps() {
            // Files-only source package (just shadcn-style components,
            // no dep declarations) is safe to land in a no-manifest
            // project — bare imports surface separately at Step 9.1.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({ "ecosystem": "js", "files": [] });

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &HashMap::new(),
                false,
            )
            .expect("no deps + no manifest must pass");
        }

        #[test]
        fn preflight_passes_under_no_install_deps_flag() {
            // The user explicitly opted out of dep installation, so
            // they accept responsibility for the consequences.
            // Preflight respects that and lets the run proceed.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &inline,
                true, // no_install_deps
            )
            .expect("--no-install-deps must bypass preflight");
        }

        #[test]
        fn preflight_passes_for_simple_path_no_lpm_config() {
            // Simple-path tarballs (no `lpm.config.json`) intentionally
            // skip auto-install entirely; the bare-imports notice at
            // Step 9.1 surfaces what the user needs. Preflight has
            // nothing to enforce here.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &None,
                &HashMap::new(),
                false,
            )
            .expect("simple-path with no lpm.config.json must pass");
        }

        // ── pm_lockfile_paths ─────────────────────────────────────────
        //
        // The per-PM lockfile snapshot list governs how broad the
        // rollback boundary is. Each arm needs its own lockfile in the
        // snapshot or an `npm install` (or pnpm/yarn/bun) partial-write
        // followed by failure leaves a manifest/lockfile split-brain
        // (the second-pass audit motivation for #9.2).

        #[test]
        fn pm_lockfile_paths_lpm_returns_empty() {
            // `lpm.lock` and `lpm.lockb` are already snapshotted by the
            // caller (the LPM lockfiles are the manifest-tx defaults);
            // returning them here would double-list and is needless.
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("lpm", dir.path());
            assert!(paths.is_empty(), "{paths:?}");
        }

        #[test]
        fn pm_lockfile_paths_npm_returns_package_lock() {
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("npm", dir.path());
            assert_eq!(paths, vec![dir.path().join("package-lock.json")]);
        }

        #[test]
        fn pm_lockfile_paths_pnpm_returns_pnpm_lock_yaml() {
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("pnpm", dir.path());
            assert_eq!(paths, vec![dir.path().join("pnpm-lock.yaml")]);
        }

        #[test]
        fn pm_lockfile_paths_yarn_returns_yarn_lock() {
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("yarn", dir.path());
            assert_eq!(paths, vec![dir.path().join("yarn.lock")]);
        }

        #[test]
        fn pm_lockfile_paths_bun_returns_both_text_and_binary_lockfiles() {
            // bun ships both `.lock` (newer text format) and `.lockb`
            // (older binary format); which one bun writes depends on
            // version + flags. Snapshot both as optional so whichever
            // bun touches is rolled back.
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("bun", dir.path());
            assert_eq!(
                paths,
                vec![dir.path().join("bun.lock"), dir.path().join("bun.lockb"),]
            );
        }

        #[test]
        fn pm_lockfile_paths_unknown_returns_empty() {
            // Defensive: `auto` is resolved to a concrete PM before the
            // snapshot, so this branch isn't reached in production.
            // But returning empty for unknown values keeps the
            // contract simple — the dispatch arm handles the unknown-
            // pm error message.
            let dir = tempfile::tempdir().unwrap();
            assert!(pm_lockfile_paths("unknown", dir.path()).is_empty());
            assert!(pm_lockfile_paths("auto", dir.path()).is_empty());
            assert!(pm_lockfile_paths("", dir.path()).is_empty());
        }
    }
}
