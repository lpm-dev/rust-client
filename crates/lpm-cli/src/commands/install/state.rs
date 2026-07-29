use super::*;

pub(super) fn write_post_install_hash(
    project_dir: &Path,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    dependency_engine_policy: &crate::engine_check::DependencyEnginePolicy,
) {
    let lock = lpm_common::read_text_file_capped(
        &project_dir.join("lpm.lock"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .unwrap_or_default();
    let dependency_engine_key = dependency_engine_policy.freshness_key(&lock);
    let node_runtime_fingerprint = match dependency_engine_key.as_str() {
        "none" | "legacy" => None,
        _ => dependency_engine_policy.resolved_node_runtime_fingerprint(),
    };
    if let Err(e) = write_post_install_hash_with_context(
        project_dir,
        linker_mode,
        object_integrity_policy,
        &dependency_engine_key,
        node_runtime_fingerprint,
    ) {
        tracing::warn!(
            "failed to write `.lpm/install-hash` after install ({e}) — \
             the next freshness check will fall through to the slow path"
        );
    }
}

fn write_post_install_hash_with_context(
    project_dir: &Path,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    dependency_engine_key: &str,
    node_runtime_fingerprint: Option<&str>,
) -> std::io::Result<()> {
    let pkg = lpm_common::read_text_file_capped(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .unwrap_or_default();
    let lock = lpm_common::read_text_file_capped(
        &project_dir.join("lpm.lock"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .unwrap_or_default();
    let file_link_bytes = crate::install_state::collect_file_link_manifest_bytes(project_dir, &pkg);
    let platform = lpm_store::v2::PlatformTuple::current();
    let hash = crate::install_state::compute_install_hash_v9(
        &pkg,
        &lock,
        &file_link_bytes,
        linker_mode,
        object_integrity_policy,
        &platform,
        dependency_engine_key,
    );
    // Lockfile writeback has already created a supported sidecar or removed an
    // unsupported one, so existence records the exact completed install state.
    let binary_sidecar_required = project_dir
        .join(lpm_lockfile::BINARY_LOCKFILE_NAME)
        .exists();
    crate::install_state::write_install_hash_with_known_runtime_state(
        project_dir,
        &hash,
        linker_mode,
        object_integrity_policy,
        &platform,
        dependency_engine_key,
        crate::install_state::KnownInstallHashRuntimeState {
            node_runtime_fingerprint,
            binary_sidecar_required,
        },
    )
}

pub(super) fn refresh_post_install_hash_after_manifest_finalize(
    project_dir: &Path,
) -> Result<(), LpmError> {
    let state_path = project_dir.join(".lpm").join("install-hash");
    let content =
        lpm_common::read_text_file_capped(&state_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
                LpmError::Registry(format!(
                    "failed to read {} after finalizing package.json: {e}",
                    state_path.display(),
                ))
            })?;
    let mut lines = content.lines();
    let _stored_hash = lines.next();
    let _stored_mtimes = lines.next();
    let linker_mode = lines
        .next()
        .and_then(|line| line.strip_prefix("l:"))
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "{} is missing its linker mode",
                state_path.display(),
            ))
        })
        .and_then(|value| {
            lpm_linker::LinkerMode::parse_str(value).map_err(|e| {
                LpmError::Registry(format!(
                    "{} contains an invalid linker mode: {e}",
                    state_path.display(),
                ))
            })
        })?;
    let object_integrity_policy = lines
        .next()
        .and_then(|line| line.strip_prefix("i:"))
        .and_then(lpm_store::v2::ObjectIntegrityPolicy::parse)
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "{} contains an invalid object integrity policy",
                state_path.display(),
            ))
        })?;
    let _stored_platform = lines.next();
    let dependency_engine_key = lines
        .next()
        .and_then(|line| line.strip_prefix("e:"))
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "{} is missing its dependency engine state",
                state_path.display(),
            ))
        })?;
    let node_runtime_fingerprint = lines
        .next()
        .and_then(|line| line.strip_prefix("n:"))
        .filter(|value| *value != "none");

    write_post_install_hash_with_context(
        project_dir,
        linker_mode,
        object_integrity_policy,
        dependency_engine_key,
        node_runtime_fingerprint,
    )
    .map_err(|e| {
        LpmError::Registry(format!(
            "failed to refresh {} after finalizing package.json: {e}",
            state_path.display(),
        ))
    })
}

pub(super) struct InstallFreshnessInput<'a> {
    pub(super) client: &'a RegistryClient,
    pub(super) project_dir: &'a Path,
    pub(super) pkg_json_path: &'a Path,
    pub(super) lockfile_path: &'a Path,
    pub(super) manifest_deps: &'a HashMap<String, String>,
    pub(super) production_dependency_names: &'a HashSet<String>,
    pub(super) policy_extension_configs: &'a [policy_extensions::PolicyExtensionConfig],
    pub(super) force: bool,
    pub(super) offline: bool,
    pub(super) no_skills: bool,
    pub(super) omit_policy: InstallOmitPolicy,
    pub(super) strict_peer_dependencies: bool,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    pub(super) dependency_engine_policy: &'a crate::engine_check::DependencyEnginePolicy,
    pub(super) store_version: lpm_store::StoreVersion,
    pub(super) compatibility_bin_names: &'a [String],
    pub(super) requested_add_count: Option<usize>,
    pub(super) json_output: bool,
    pub(super) emit_timing: bool,
    pub(super) timing_detail_mode: TimingDetailMode,
    pub(super) force_security_floor: bool,
    pub(super) target_set: Option<&'a [String]>,
    pub(super) emit_install_report: bool,
    pub(super) install_accounting: ManagedInstallAccounting,
    pub(super) start: Instant,
}

pub(super) struct InstallFreshnessResult {
    pub(super) setup_install_state_ms: u128,
    pub(super) cleanup_catalogs_in_pipeline: bool,
    pub(super) completed: bool,
}

pub(super) async fn run_install_freshness_phase(
    input: InstallFreshnessInput<'_>,
) -> Result<InstallFreshnessResult, LpmError> {
    let pkg_content_for_state = lpm_common::read_text_file_capped(
        input.pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .unwrap_or_default();
    let setup_state_t = Instant::now();
    let dependency_engine_key = dependency_engine_freshness_key_for_state(
        input.project_dir,
        input.lockfile_path,
        input.dependency_engine_policy,
    );
    let install_state =
        crate::install_state::check_install_state_with_linker_integrity_and_dependency_engine(
            input.project_dir,
            &pkg_content_for_state,
            input.linker_mode,
            input.object_integrity_policy,
            &dependency_engine_key,
            input.store_version,
        );
    let setup_install_state_ms = setup_state_t.elapsed().as_millis();
    let compatibility_bins_ready = !input.store_version.is_v2()
        || input.compatibility_bin_names.is_empty()
        || lpm_linker::v2::project_compatibility_bins_ready(
            input.project_dir,
            input.compatibility_bin_names,
        );
    let cleanup_catalogs_in_pipeline = input.requested_add_count.is_none();
    let fast_path_base_eligible = !input.force
        && !input.offline
        && (input.no_skills
            || crate::commands::skills::package::materialization_complete(
                input.project_dir,
                &pkg_content_for_state,
            ))
        && input.omit_policy.is_default()
        && !input.strict_peer_dependencies
        && install_state.up_to_date
        && compatibility_bins_ready;
    let fast_path_packages = if fast_path_base_eligible {
        let gate_stats = GateStats::default();
        if let Some(fast) = try_lockfile_fast_path(
            input.lockfile_path,
            input.manifest_deps,
            &[],
            input.client,
            &gate_stats,
            false,
        ) {
            let mut packages = fast.packages;
            if input.omit_policy.dev {
                filter_dev_packages(&mut packages, input.production_dependency_names);
            }
            filter_dependency_engine_packages(&mut packages, input.dependency_engine_policy)?;
            filter_platform_packages(&mut packages)?;
            Some(packages)
        } else {
            None
        }
    } else {
        None
    };
    let fast_path_policy_extension_stats = match (
        fast_path_packages.as_deref(),
        input.policy_extension_configs.is_empty(),
    ) {
        (Some(_), true) => None,
        (Some(packages), false) => Some(
            run_policy_extensions(
                input.policy_extension_configs,
                input.project_dir,
                packages,
                input.json_output,
            )
            .await?,
        ),
        (None, _) => None,
    };
    if fast_path_base_eligible
        && let Some(fast_path_packages) = fast_path_packages.as_deref()
        && (input.policy_extension_configs.is_empty() || fast_path_policy_extension_stats.is_some())
    {
        let policy_extension_stats = if let Some(stats) = fast_path_policy_extension_stats {
            stats
        } else {
            run_policy_extensions(
                input.policy_extension_configs,
                input.project_dir,
                &[],
                input.json_output,
            )
            .await?
        };
        let catalogs_cleaned = if cleanup_catalogs_in_pipeline {
            cleanup_unused_catalogs_after_install(input.project_dir)?
        } else {
            false
        };
        if catalogs_cleaned {
            write_post_install_hash(
                input.project_dir,
                input.linker_mode,
                input.object_integrity_policy,
                input.dependency_engine_policy,
            );
        }
        report_pool_install_attribution(input.client, fast_path_packages, input.install_accounting)
            .await?;
        let elapsed = input.start.elapsed();
        let total_ms = elapsed.as_millis();
        if input.emit_install_report {
            if input.json_output {
                let mut json = serde_json::json!({
                    "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
                    "success": true,
                    "up_to_date": true,
                    "duration_ms": total_ms as u64,
                    "timing": {
                        "resolve_ms": 0u128,
                        "fetch_ms": 0u128,
                        "link_ms": 0u128,
                        "total_ms": total_ms,
                        "waterfall": {
                            "setup_ms": total_ms,
                            "resolve_ms": 0u128,
                            "pre_fetch_ms": 0u128,
                            "fetch_ms": 0u128,
                            "pre_link_ms": 0u128,
                            "link_ms": 0u128,
                            "link_await_ms": 0u128,
                            "link_finalize_ms": 0u128,
                            "tail_ms": 0u128,
                            "total_ms": total_ms,
                        },
                    },
                    "peer_conflicts": [],
                    "peer_issues": peer_issues_json_value(&[], &[]),
                    "security": {
                        "policy_extensions": policy_extension_stats.to_json(),
                    },
                });
                json["timing"]["policy_extensions"] = policy_extension_stats.to_json();
                if input.timing_detail_mode.enabled() {
                    json["timing"]["detail"] = setup_only_timing_detail_json(
                        input.timing_detail_mode,
                        total_ms,
                        setup_install_state_ms,
                        0,
                    );
                }
                if !input.emit_timing
                    && let Some(obj) = json.as_object_mut()
                {
                    obj.remove("timing");
                }
                if let Some(targets) = input.target_set {
                    json["target_set"] = serde_json::Value::Array(
                        targets.iter().map(|s| serde_json::json!(s)).collect(),
                    );
                }
                crate::security_floor::attach_security_posture(
                    &mut json,
                    input.force_security_floor,
                );
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                install_ui::done_untrusted(&format!("Up to date · {total_ms}ms"));
            }
        }
        return Ok(InstallFreshnessResult {
            setup_install_state_ms,
            cleanup_catalogs_in_pipeline,
            completed: true,
        });
    }

    Ok(InstallFreshnessResult {
        setup_install_state_ms,
        cleanup_catalogs_in_pipeline,
        completed: false,
    })
}

fn dependency_engine_freshness_key_for_state(
    project_dir: &Path,
    lockfile_path: &Path,
    policy: &crate::engine_check::DependencyEnginePolicy,
) -> String {
    let state_path = project_dir.join(".lpm").join("install-hash");
    if let Ok(state) =
        lpm_common::read_text_file_capped(&state_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        && let Some(cached) = parse_cached_dependency_engine_state(&state)
    {
        if matches!(cached.key, "none" | "legacy") {
            return cached.key.to_string();
        }

        let probed_fingerprint = policy.probe_node_runtime_fingerprint();
        let decision = decide_dependency_engine_freshness(
            cached.key,
            cached.runtime_fingerprint,
            probed_fingerprint.as_deref(),
            policy.can_reuse_constrained_freshness_key(cached.key),
            || {
                let key = policy.constrained_freshness_key();
                let runtime_fingerprint = policy
                    .resolved_node_runtime_fingerprint()
                    .map(str::to_owned);
                ResolvedDependencyEngineFreshness {
                    key,
                    runtime_fingerprint,
                }
            },
        );
        if let RuntimeFingerprintUpdate::Replace(runtime_fingerprint) =
            &decision.runtime_fingerprint_update
            && let Err(error) = crate::install_state::refresh_install_hash_node_runtime_fingerprint(
                project_dir,
                cached.key,
                runtime_fingerprint.as_deref(),
            )
        {
            tracing::debug!(
                "failed to refresh cached Node runtime fingerprint after revalidation: {error}"
            );
        }
        return decision.key;
    }

    let lockfile = std::fs::read_to_string(lockfile_path).unwrap_or_default();
    policy.freshness_key(&lockfile)
}

struct CachedDependencyEngineState<'a> {
    key: &'a str,
    runtime_fingerprint: Option<&'a str>,
}

fn parse_cached_dependency_engine_state(state: &str) -> Option<CachedDependencyEngineState<'_>> {
    let mut key = None;
    let mut runtime_fingerprint = None;
    let mut saw_runtime_fingerprint = false;

    for line in state.lines() {
        if let Some(value) = line.strip_prefix("e:")
            && key.replace(value).is_some()
        {
            return None;
        }
        if let Some(value) = line.strip_prefix("n:") {
            if saw_runtime_fingerprint {
                runtime_fingerprint = None;
                continue;
            }
            saw_runtime_fingerprint = true;
            if crate::install_state::is_node_runtime_fingerprint(value) {
                runtime_fingerprint = Some(value);
            }
        }
    }

    Some(CachedDependencyEngineState {
        key: key?,
        runtime_fingerprint,
    })
}

struct ResolvedDependencyEngineFreshness {
    key: String,
    runtime_fingerprint: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
enum RuntimeFingerprintUpdate {
    Keep,
    Replace(Option<String>),
}

struct DependencyEngineFreshnessDecision {
    key: String,
    runtime_fingerprint_update: RuntimeFingerprintUpdate,
}

fn decide_dependency_engine_freshness(
    stored_key: &str,
    stored_fingerprint: Option<&str>,
    probed_fingerprint: Option<&str>,
    stored_key_matches_current_policy: bool,
    revalidate: impl FnOnce() -> ResolvedDependencyEngineFreshness,
) -> DependencyEngineFreshnessDecision {
    if stored_key_matches_current_policy
        && stored_fingerprint
            .zip(probed_fingerprint)
            .is_some_and(|(stored, probed)| stored == probed)
    {
        return DependencyEngineFreshnessDecision {
            key: stored_key.to_string(),
            runtime_fingerprint_update: RuntimeFingerprintUpdate::Keep,
        };
    }

    let resolved = revalidate();
    let runtime_fingerprint_update = if resolved.key == stored_key {
        RuntimeFingerprintUpdate::Replace(resolved.runtime_fingerprint)
    } else {
        RuntimeFingerprintUpdate::Keep
    };
    DependencyEngineFreshnessDecision {
        key: resolved.key,
        runtime_fingerprint_update,
    }
}

/// Empty installs still need the same durable on-disk markers the
/// freshness cache keys on: `lpm.lock`, `node_modules/`, and the
/// standard `lpm.lockb`/`.gitattributes` sidecar written by the main
/// lockfile path. Without these, the empty-deps short-circuit would
/// succeed once but never become warm-cache fresh, so every later
/// `lpm install`, `lpm dev`, and sync fast-lane probe would fall back
/// to the slow path despite the manifest already being fully applied.
pub(super) fn materialize_empty_install_artifacts(project_dir: &Path) -> Result<(), LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    lpm_lockfile::Lockfile::default()
        .write_all(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to write empty lockfile: {e}")))?;

    lpm_lockfile::ensure_gitattributes(project_dir)
        .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

    std::fs::create_dir_all(project_dir.join("node_modules")).map_err(LpmError::Io)?;
    Ok(())
}

#[cfg(test)]
mod dependency_engine_freshness_tests {
    use super::*;
    use std::cell::Cell;

    const FINGERPRINT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FINGERPRINT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn matching_runtime_fingerprint_reuses_key_without_revalidation() {
        let revalidation_count = Cell::new(0);

        let decision = decide_dependency_engine_freshness(
            "1:22.0.0",
            Some(FINGERPRINT_A),
            Some(FINGERPRINT_A),
            true,
            || {
                revalidation_count.set(revalidation_count.get() + 1);
                ResolvedDependencyEngineFreshness {
                    key: "1:22.0.0".to_string(),
                    runtime_fingerprint: Some(FINGERPRINT_A.to_string()),
                }
            },
        );

        assert_eq!(decision.key, "1:22.0.0");
        assert_eq!(revalidation_count.get(), 0);
    }

    #[test]
    fn changed_runtime_fingerprint_invokes_revalidation() {
        let revalidation_count = Cell::new(0);

        decide_dependency_engine_freshness(
            "1:22.0.0",
            Some(FINGERPRINT_A),
            Some(FINGERPRINT_B),
            true,
            || {
                revalidation_count.set(revalidation_count.get() + 1);
                ResolvedDependencyEngineFreshness {
                    key: "1:22.0.0".to_string(),
                    runtime_fingerprint: Some(FINGERPRINT_B.to_string()),
                }
            },
        );

        assert_eq!(revalidation_count.get(), 1);
    }

    #[test]
    fn missing_runtime_fingerprint_invokes_revalidation() {
        let revalidation_count = Cell::new(0);

        decide_dependency_engine_freshness("1:22.0.0", None, Some(FINGERPRINT_A), true, || {
            revalidation_count.set(revalidation_count.get() + 1);
            ResolvedDependencyEngineFreshness {
                key: "1:22.0.0".to_string(),
                runtime_fingerprint: Some(FINGERPRINT_A.to_string()),
            }
        });

        assert_eq!(revalidation_count.get(), 1);
    }

    #[test]
    fn same_version_after_runtime_change_refreshes_fingerprint() {
        let decision = decide_dependency_engine_freshness(
            "1:22.0.0",
            Some(FINGERPRINT_A),
            Some(FINGERPRINT_B),
            true,
            || ResolvedDependencyEngineFreshness {
                key: "1:22.0.0".to_string(),
                runtime_fingerprint: Some(FINGERPRINT_B.to_string()),
            },
        );

        assert_eq!(
            decision.runtime_fingerprint_update,
            RuntimeFingerprintUpdate::Replace(Some(FINGERPRINT_B.to_string()))
        );
    }

    #[test]
    fn changed_version_invalidates_without_refreshing_old_state() {
        let decision = decide_dependency_engine_freshness(
            "1:22.0.0",
            Some(FINGERPRINT_A),
            Some(FINGERPRINT_B),
            true,
            || ResolvedDependencyEngineFreshness {
                key: "1:23.0.0".to_string(),
                runtime_fingerprint: Some(FINGERPRINT_B.to_string()),
            },
        );

        assert_eq!(decision.key, "1:23.0.0");
        assert_eq!(
            decision.runtime_fingerprint_update,
            RuntimeFingerprintUpdate::Keep
        );
    }

    #[test]
    fn malformed_runtime_fingerprint_is_not_reusable() {
        let cached =
            parse_cached_dependency_engine_state("hash\ne:1:22.0.0\nn:not-a-valid-fingerprint\n")
                .unwrap();

        assert_eq!(cached.runtime_fingerprint, None);
    }

    #[test]
    fn strictness_change_invokes_revalidation_even_when_fingerprint_matches() {
        let revalidation_count = Cell::new(0);

        decide_dependency_engine_freshness(
            "1:22.0.0",
            Some(FINGERPRINT_A),
            Some(FINGERPRINT_A),
            false,
            || {
                revalidation_count.set(revalidation_count.get() + 1);
                ResolvedDependencyEngineFreshness {
                    key: "0:22.0.0".to_string(),
                    runtime_fingerprint: Some(FINGERPRINT_A.to_string()),
                }
            },
        );

        assert_eq!(revalidation_count.get(), 1);
    }
}
