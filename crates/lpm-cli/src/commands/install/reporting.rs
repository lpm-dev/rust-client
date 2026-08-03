use lpm_linker::LinkResult;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::*;

pub(super) struct OnlineInstallReportInput<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) lockfile_path: &'a Path,
    pub(super) packages: &'a [InstallPackage],
    pub(super) downloaded: usize,
    pub(super) cached: usize,
    pub(super) link_result: &'a LinkResult,
    pub(super) used_lockfile: bool,
    pub(super) elapsed: Duration,
    pub(super) emit_timing: bool,
    pub(super) json_output: bool,
    pub(super) target_set: Option<&'a [String]>,
    pub(super) workspace_member_deps: &'a [WorkspaceMemberLink],
    pub(super) applied_overrides: &'a [OverrideHit],
    pub(super) override_set: &'a OverrideSet,
    pub(super) peer_warnings: &'a [PeerWarning],
    pub(super) peer_conflicts: &'a [PeerConflictReport],
    pub(super) current_patches: &'a HashMap<String, PatchedDependencyEntry>,
    pub(super) current_patch_fingerprint: &'a str,
    pub(super) applied_patches: &'a [patch_engine::AppliedPatch],
    pub(super) blocked_capture: &'a crate::build_state::BlockedSetCapture,
    pub(super) install_provenance_status_map:
        &'a HashMap<(String, String), lpm_common::ProvenanceStatus>,
    pub(super) audit_summary_for_envelope: &'a Option<crate::commands::audit::AuditCounts>,
    pub(super) force_security_floor: bool,
    pub(super) timing_detail_mode: TimingDetailMode,
    pub(super) resolve_ms: u128,
    pub(super) fetch_ms: u128,
    pub(super) link_ms: u128,
    pub(super) npm_firewall_stats: &'a NpmFirewallPreflightStats,
    pub(super) policy_extension_stats: &'a PolicyExtensionStats,
    pub(super) gate_stats: &'a GateStats,
    pub(super) wf_setup_ms: u128,
    pub(super) wf_resolve_end_ms: u128,
    pub(super) wf_materialization_wait_ms: u128,
    pub(super) wf_commit_wait_ms: u128,
    pub(super) wf_fetch_start_ms: u128,
    pub(super) wf_fetch_end_ms: u128,
    pub(super) wf_link_start_ms: u128,
    pub(super) wf_link_end_ms: u128,
    pub(super) wf_link_await_ms: u128,
    pub(super) wf_link_finalize_ms: u128,
    pub(super) wf_link_reconcile_ms: u128,
    pub(super) wf_link_root_symlinks_ms: u128,
    pub(super) wf_link_compatibility_ms: u128,
    pub(super) wf_link_bin_shims_ms: u128,
    pub(super) wf_setup_install_state_ms: u128,
    pub(super) wf_setup_route_table_ms: u128,
    pub(super) wf_tail_blocked_metadata_ms: u128,
    pub(super) wf_tail_trust_snapshot_ms: u128,
    pub(super) wf_tail_lockfile_write_ms: u128,
    pub(super) wf_tail_lockfile_write_count: u64,
    pub(super) wf_tail_audit_after_install_ms: u128,
    pub(super) registry_signature_timings:
        &'a Option<Arc<crate::registry_signatures::RegistrySignatureTimings>>,
    pub(super) provenance_timings: &'a Option<crate::provenance_fetch::ProvenanceTimings>,
    pub(super) fetch_stage_timings: FetchStageTimings,
    pub(super) fetch_breakdown: FetchBreakdown,
    pub(super) walker_summary_final: &'a Option<lpm_resolver::WalkerSummary>,
    pub(super) streaming_metrics: &'a lpm_resolver::StreamingBfsMetrics,
    pub(super) initial_batch_ms: u128,
    pub(super) resolver_stage_timing: &'a lpm_resolver::StageTiming,
    pub(super) platform_skipped: usize,
    pub(super) spec_stats: SpeculativeStats,
    pub(super) v2_link_task_timings: V2LinkTaskTimings,
    pub(super) slow_package_timings: &'a SlowPackageTimings,
    pub(super) pre_install_direct_versions: &'a HashMap<String, String>,
    pub(super) latest_stable_versions: &'a HashMap<String, String>,
    pub(super) is_add_invocation: bool,
    pub(super) verbose: bool,
}

pub(super) fn emit_online_install_report(input: OnlineInstallReportInput<'_>) {
    let OnlineInstallReportInput {
        project_dir,
        lockfile_path,
        packages,
        downloaded,
        cached,
        link_result,
        used_lockfile,
        elapsed,
        emit_timing,
        json_output,
        target_set,
        workspace_member_deps,
        applied_overrides,
        override_set,
        peer_warnings,
        peer_conflicts,
        current_patches,
        current_patch_fingerprint,
        applied_patches,
        blocked_capture,
        install_provenance_status_map,
        audit_summary_for_envelope,
        force_security_floor,
        timing_detail_mode,
        resolve_ms,
        fetch_ms,
        link_ms,
        npm_firewall_stats,
        policy_extension_stats,
        gate_stats,
        wf_setup_ms,
        wf_resolve_end_ms,
        wf_materialization_wait_ms,
        wf_commit_wait_ms,
        wf_fetch_start_ms,
        wf_fetch_end_ms,
        wf_link_start_ms,
        wf_link_end_ms,
        wf_link_await_ms,
        wf_link_finalize_ms,
        wf_link_reconcile_ms,
        wf_link_root_symlinks_ms,
        wf_link_compatibility_ms,
        wf_link_bin_shims_ms,
        wf_setup_install_state_ms,
        wf_setup_route_table_ms,
        wf_tail_blocked_metadata_ms,
        wf_tail_trust_snapshot_ms,
        wf_tail_lockfile_write_ms,
        wf_tail_lockfile_write_count,
        wf_tail_audit_after_install_ms,
        registry_signature_timings,
        provenance_timings,
        fetch_stage_timings,
        fetch_breakdown,
        walker_summary_final,
        streaming_metrics,
        initial_batch_ms,
        resolver_stage_timing,
        platform_skipped,
        spec_stats,
        v2_link_task_timings,
        slow_package_timings,
        pre_install_direct_versions,
        latest_stable_versions,
        is_add_invocation,
        verbose,
    } = input;

    if json_output {
        let metadata_http_versions = lpm_registry::timing::snapshot_metadata_http_versions();
        let timing_metadata_detail = if timing_detail_mode.enabled() {
            Some(metadata_detail_snapshots())
        } else {
            None
        };
        let resolve_wall_ms = wf_resolve_end_ms.saturating_sub(wf_setup_ms);
        let post_resolve_ms = post_resolve_work_ms(
            wf_resolve_end_ms,
            wf_materialization_wait_ms,
            wf_fetch_start_ms,
        );
        let pre_link_ms = pre_link_work_ms(wf_fetch_end_ms, wf_commit_wait_ms, wf_link_start_ms);
        let fetch_wall_ms = wf_fetch_end_ms.saturating_sub(wf_fetch_start_ms);
        let counts = InstallCountSemantics {
            resolved_package_row_count: packages.len(),
            authoritative_fetch_candidate_count: downloaded,
            store_reuse_observation_count: cached,
            linker_entry_created_count: link_result.linked,
            linker_entry_reused_count: link_result.skipped,
            project_root_symlink_created_count: link_result.symlinked,
            bin_link_created_count: link_result.bin_linked,
        }
        .to_json();
        let metadata_dispatcher = metadata_dispatcher_json(resolver_stage_timing);
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let mut json = serde_json::json!({
                   "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
                   "success": true,
                   "packages": pkg_list,
                   "count": packages.len(),
                   "downloaded": downloaded,
                   "cached": cached,
                   "linked": link_result.linked,
                   "symlinked": link_result.symlinked,
                   "used_lockfile": used_lockfile,
                   "duration_ms": elapsed.as_millis() as u64,
                   "timing": {
                       "resolve_ms": resolve_ms,
                       "firewall_batch_ms": npm_firewall_stats.batch_ms,
                       "firewall": npm_firewall_stats.to_json(),
                       "fetch_ms": fetch_ms,
                       "link_ms": link_ms,
                       "total_ms": elapsed.as_millis(),
                       "waterfall": {
                           "setup_ms": wf_setup_ms,
                           "resolve_ms": wf_resolve_end_ms.saturating_sub(wf_setup_ms),
                           "materialization_wait_ms": wf_materialization_wait_ms,
                           "commit_wait_ms": wf_commit_wait_ms,
                           "post_resolve_work_ms": post_resolve_ms,
                           "pre_fetch_ms": post_resolve_ms,
                           "fetch_ms": wf_fetch_end_ms.saturating_sub(wf_fetch_start_ms),
                           "pre_link_ms": pre_link_ms,
                           "link_ms": wf_link_end_ms.saturating_sub(wf_link_start_ms),
                           "link_await_ms": wf_link_await_ms,
                           "link_finalize_ms": wf_link_finalize_ms,
                           "tail_ms": elapsed.as_millis().saturating_sub(wf_link_end_ms),
                           "total_ms": elapsed.as_millis(),
                       },
        // Nested resolver breakdown:
        //
        // seeded this object with `platform_skipped`.
        // grows with the cold-resolve substage
        // breakdown so consumers can attribute `resolve_ms`
        // to a specific contributor before work starts on
        // (deeper worker walk) / (parallel follow-
        // ups) /d (slim batch response).
        //
        // Field shape:
        // platform_skipped — optional deps filtered by os/cpu ()
        // initial_batch_ms — wall-clock from
        // orchestration start to the
        // moment the resolver could begin
        // solving (walker's roots_ready
        // signal). The new-shape analog
        // of the pre-49 "batch prefetch
        // done" timestamp. On
        // lockfile-fast-path, zero.
        // Does NOT include PubGrub
        // wall-clock (reported separately
        // as `pubgrub_ms`).
        // followup_rpc_ms — metadata RPCs fired by the
        // resolver's PubGrub callbacks
        // (theb/ lever).
        // followup_rpc_count — count of those follow-up RPCs.
        // parse_ndjson_ms — serde_json CPU time for
        // follow-up batches ( lever).
        // pubgrub_ms — wall-clock inside
        // `pubgrub::resolve()` (includes
        // provider callbacks).
        //
        // `resolve_ms` stays as a top-level scalar for
        // backwards compatibility; the substages inside
        // `resolve` are additive observability.
                       "resolve": {
                           "platform_skipped": platform_skipped,
                           "initial_batch_ms": initial_batch_ms,
                           "followup_rpc_ms": resolver_stage_timing.followup_rpc_ms,
                           "followup_rpc_count": resolver_stage_timing.followup_rpc_count,
        // A1 — split formerly-conflated count into
        // walker-driven and escape-hatch buckets so
        // operators can tell whether the walker covered the
        // tree or the resolver picked up slack via direct
        // fetches. Sum of these two equals followup_rpc_count.
        //
        // zero on the fused dispatcher arm
        // (`LPM_GREEDY_FUSION=1`); see `dispatcher.*`
        // below. Retained for one release; removed in.
                           "walker_rpc_count": resolver_stage_timing.walker_rpc_count,
                           "escape_hatch_rpc_count": resolver_stage_timing.escape_hatch_rpc_count,
                           "parse_ndjson_ms": resolver_stage_timing.parse_ndjson_ms,
                           "pubgrub_ms": resolver_stage_timing.pubgrub_ms,
                           "metadata_http_versions": {
                               "http_09": metadata_http_versions.http_09,
                               "http_10": metadata_http_versions.http_10,
                               "http_11": metadata_http_versions.http_11,
                               "http_2": metadata_http_versions.http_2,
                               "http_3": metadata_http_versions.http_3,
                               "unknown": metadata_http_versions.unknown,
                           },
        // — fused metadata-dispatcher counters. Zero on
        // the walker arm; populated under greedy fusion.
        // Field shape:
        // rpc_count — total metadata RPCs the
        // dispatcher fired
        // (replaces walker +
        // escape_hatch on fusion).
        // inflight_high_water — peak in-flight metadata
        // fetches; approaching the
        // configured fanout means the
        // semaphore is binding.
        // parked_max_depth — peak Vec length in the
        // per-canonical park map;
        // healthy values are O(few),
        // hundreds = stalled CDN
        // pin on one package.
        // tarball_dispatched — speculative tarball
        // metadata frames emitted
        // by resolver arms that
        // enable CLI speculation.
        // Fusion leaves this at 0
        // by default and lets the
        // exact graph feed fetch.
        // peer_prefetch_count — speculative
        // peer-manifest fetches
        // dispatched concurrent with
        // the regular dep walk.
        // Each such fetch saved one
        // sequential round-trip from
        // the post-loop drain pass.
        //: streaming-BFS observability per
        // design. Null on warm lockfile-fast-path
        // installs (walker never ran). Field shape:
        // walk_ms — walker's metadata-producer
        // window (from
        // `WalkerSummary::walker_wall_ms`).
        // manifests_fetched — count of packages the walker
        // inserted into SharedCache.
        // cache_hits — count of names skipped because
        // SharedCache already held them
        // (walker's cache-hit path).
        // cache_waits — provider-side: PubGrub callbacks
        // that entered the wait-loop on
        // a cache miss (fast-path cache
        // hits NOT counted). NOT equal to
        // installed package count —
        // ensure_cached is called from
        // multiple sites and may re-enter
        // across split retries. Treat
        // qualitatively: "how many times
        // did PubGrub wait on the walker."
        // cache_wait_timeouts — provider-side: wait-loop exits
        // by `fetch_wait_timeout`
        // firing. Healthy 0; non-zero
        // means a sleeper waited the
        // full timeout without the
        // walker either inserting or
        // flipping `walker_done`
        // (pre-49 wait-loop shape, or
        // a regression of the
        // shutdown handshake).
        // cache_wait_walker_done_shortcuts
        // — provider-side: wait-loop
        // exits *early* because the
        // walker terminated without
        // inserting this key. The
        // healthy outcome of the
        // shutdown handshake:
        // a transient walker gap
        // (e.g. older-version dep
        // missed by newest-only
        // expansion) routes to the
        // escape-hatch in micros
        // rather than burning the
        // 5s timeout.
        // escape_hatch_fetches — provider-side: non-root fetches
        // that bypassed the wait-loop.
        // Healthy 0 when walker attached
        // and keeps ahead of PubGrub.
        // Non-zero = walker gap OR no
        // walker (pre-shape with
        // fetch_wait_timeout == ZERO).
        // Compare against
        // `cache_wait_walker_done_shortcuts`
        // to distinguish "walker had a
        // gap, recovered cheaply" (good)
        // from "walker isn't attached"
        // (no waits at all).
        // spec_tx_send_wait_ms — walker time blocked on
        // `spec_tx.send().await`
        // (dispatcher backpressure
        // canary per design).
        // max_depth — deepest BFS level the walker
        // walked (0 = roots only).
                           "streaming_bfs": walker_summary_final.as_ref().map(|s| {
        // Per-BFS-level three-phase wall breakdown. `total_ms − fetch_ms` per level is the
        // inter-fetch dead time that's
        // continuous-stream walker is designed to eliminate.
        // Empty when the walker did zero levels (warm-cache
        // full hit). Built outside the outer json! macro so
        // its expansion doesn't blow recursion_limit.
                               let levels: Vec<serde_json::Value> = s
                                   .levels
                                   .iter()
                                   .map(|l| serde_json::json!({
                                       "depth": l.depth,
                                       "seeded_count": l.seeded_count,
                                       "cache_hit_count": l.cache_hit_count,
                                       "npm_fetch_count": l.npm_fetch_count,
                                       "lpm_fetch_count": l.lpm_fetch_count,
                                       "setup_ms": l.setup_ms,
                                       "fetch_ms": l.fetch_ms,
                                       "commit_ms": l.commit_ms,
                                       "total_ms": l.total_ms,
                                   }))
                                   .collect();
                               serde_json::json!({
                                   "walk_ms": s.walker_wall_ms,
                                   "manifests_fetched": s.manifests_fetched,
                                   "cache_hits": s.cache_hits,
                                   "cache_waits": streaming_metrics.cache_waits(),
                                   "cache_wait_timeouts": streaming_metrics.cache_wait_timeouts(),
                                   "cache_wait_walker_done_shortcuts":
                                       streaming_metrics.cache_wait_walker_done_shortcuts(),
                                   "escape_hatch_fetches": streaming_metrics.escape_hatch_fetches(),
                                   "spec_tx_send_wait_ms": s.spec_tx_send_wait_ms,
                                   "max_depth": s.max_depth,
                                   "levels": levels,
                               })
                           }),
                       },
        //: sub-stage breakdown of the fetch pool. Zeroed
        // when everything is already in the store (lockfile fast path
        // with warm cache). Field shape is the `FetchBreakdown` JSON
        // contract documented on that struct.
                       "fetch_breakdown": fetch_breakdown.to_json(),
        // — lockfile-cached URL gate telemetry. All
        // counters zero when every stored URL passed (common
        // case in steady state). `origin_mismatch > 0` is
        // expected after `LPM_REGISTRY_URL` switches;
        // `shape_mismatch > 0` is a BUG signal — the writer
        // should never emit a gate-rejectable URL.
                       "tarball_url_gate": gate_stats.to_json(),
        // speculative-fetch stats. Zero when every
        // root is already in the store before the metadata RPC
        // starts, or on the lockfile-fast-path. Field shape
        // documented on `SpeculativeStats`.
                       "speculative": spec_stats.to_json(),
                   },
                   "warnings": [],
                   "errors": [],
                   "peer_conflicts": [],
                   "peer_issues": peer_issues_json_value(&[], &[]),
               });
        json["counts"] = counts;
        json["timing"]["resolve"]["dispatcher"] = metadata_dispatcher.clone();
        json["timing"]["resolve"]["metadata_dispatcher"] = metadata_dispatcher;
        json["security"] = serde_json::json!({
            "firewall": npm_firewall_stats.to_json(),
            "policy_extensions": policy_extension_stats.to_json(),
        });
        json["timing"]["policy_extensions"] = policy_extension_stats.to_json();
        if timing_detail_mode.enabled() {
            let build_state_write_timing = crate::build_state::snapshot_write_timing();
            let metadata_snapshots = timing_metadata_detail.as_deref().unwrap_or(&[]);
            let mut detail = serde_json::json!({
                "setup": {
                    "install_state_ms": wf_setup_install_state_ms,
                    "route_table_ms": wf_setup_route_table_ms,
                    "other_ms": wf_setup_ms.saturating_sub(
                        wf_setup_install_state_ms.saturating_add(wf_setup_route_table_ms),
                    ),
                },
                "metadata": metadata_detail_json_from_snapshots(
                    metadata_snapshots,
                    timing_detail_mode,
                ),
                "resolve": resolve_detail_json(
                    resolve_wall_ms,
                    initial_batch_ms,
                    resolver_stage_timing,
                    metadata_snapshots,
                    timing_detail_mode,
                ),
                "fetch": fetch_stage_timings.to_json(
                    fetch_wall_ms,
                    packages.len(),
                    cached,
                    downloaded,
                    fetch_breakdown,
                ),
                "security": {
                    "firewall": npm_firewall_stats.to_json(),
                    "policy_extensions": policy_extension_stats.to_json(),
                    "registry_signatures": registry_signature_timings
                        .as_ref()
                        .map_or(serde_json::Value::Null, |timings| timings.to_json()),
                    "provenance": provenance_timings
                        .as_ref()
                        .map_or(serde_json::Value::Null, |timings| timings.to_json()),
                },
                "link": {
                    "reconcile_ms": wf_link_reconcile_ms,
                    "root_symlinks_ms": wf_link_root_symlinks_ms,
                    "compatibility_ms": wf_link_compatibility_ms,
                    "bin_shims_ms": wf_link_bin_shims_ms,
                    "v2_one": v2_link_task_timings.to_json(wf_link_await_ms),
                },
                "tail": {
                    "blocked_metadata_ms": wf_tail_blocked_metadata_ms,
                    "trust_snapshot_ms": wf_tail_trust_snapshot_ms,
                    "lockfile_write_ms": wf_tail_lockfile_write_ms,
                    "lockfile_write_count": wf_tail_lockfile_write_count,
                    "build_state_write_ms": build_state_write_timing.write_ms,
                    "build_state_write_count": build_state_write_timing.write_count,
                    "audit_after_install_ms": wf_tail_audit_after_install_ms,
                    "other_ms": elapsed
                        .as_millis()
                        .saturating_sub(wf_link_end_ms)
                        .saturating_sub(wf_tail_blocked_metadata_ms)
                        .saturating_sub(wf_tail_trust_snapshot_ms)
                        .saturating_sub(wf_tail_lockfile_write_ms)
                        .saturating_sub(build_state_write_timing.write_ms as u128)
                        .saturating_sub(wf_tail_audit_after_install_ms),
                },
            });
            if timing_detail_mode.trace() {
                let mut slow_packages = slow_package_timings.to_json();
                if let serde_json::Value::Object(slow_packages) = &mut slow_packages {
                    slow_packages.insert(
                        "provenance_verify".to_string(),
                        provenance_timings.as_ref().map_or_else(
                            || serde_json::Value::Array(Vec::new()),
                            crate::provenance_fetch::ProvenanceTimings::slow_verify_json,
                        ),
                    );
                }
                detail["trace"] = serde_json::json!({
                    "slow_packages": slow_packages,
                });
            }
            json["timing"]["detail"] = detail;
        }
        attach_target_timing_semantics(&mut json["timing"]);
        if !emit_timing && let Some(obj) = json.as_object_mut() {
            obj.remove("timing");
        }
        // surface workspace target set for agents.
        // None for legacy/standalone callers; Some(...) for the filtered path.
        if let Some(targets) = target_set {
            json["target_set"] =
                serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
        }
        // invariant: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // surface the override apply trace. Empty
        // when no overrides were declared OR when the lockfile fast
        // path was taken (in which case the persisted state file holds
        // the most recent trace from a fresh resolve).
        if !applied_overrides.is_empty() {
            json["applied_overrides"] = serde_json::Value::Array(
                applied_overrides
                    .iter()
                    .map(|h| {
                        serde_json::json!({
                            "raw_key": h.raw_key,
                            "source": h.source,
                            "package": h.package,
                            "from_version": h.from_version,
                            "to_version": h.to_version,
                            "via_parent": h.via_parent,
                        })
                    })
                    .collect(),
            );
        }
        json["overrides_count"] = serde_json::json!(override_set.len());
        json["overrides_fingerprint"] =
            fingerprint_json_value(override_set.len(), override_set.fingerprint());

        // best-effort peer-
        // conflict reports as an ALWAYS-PRESENT array. Empty when the
        // peer graph is clean OR on the lockfile fast path (no fresh
        // resolve produces no fresh conflict trace). Field is
        // unconditional so machine consumers can rely on its
        // existence — same shape contract as `applied_patches`.
        json["peer_conflicts"] = serde_json::Value::Array(
            peer_conflicts
                .iter()
                .map(peer_conflict_json_value)
                .collect(),
        );
        json["peer_issues"] = peer_issues_json_value(peer_warnings, peer_conflicts);

        // surface the patch apply trace + counts.
        // invariant : filter to entries that ACTUALLY did
        // work this run via `touched_anything()`. A no-op idempotent
        // rerun where every file already had the expected post-patch
        // bytes will report an empty `applied_patches` array — that's
        // the correct per-run signal. The patches are still in effect
        // (the state file still records them), but we did no work, so
        // we don't claim we did. Always emitted so agents can rely on
        // the field's existence.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] =
            fingerprint_json_value(current_patches.len(), current_patch_fingerprint);

        // surface the install-time blocked set so
        // agents and CI can drive `lpm approve-scripts` without re-scanning.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] = fingerprint_json_value(
            blocked_capture.state.blocked_packages.len(),
            blocked_capture.state.blocked_set_fingerprint.clone(),
        );
        // + per-entry shape now
        // includes `static_tier` () and `version_diff` () via
        // the shared `version_diff::blocked_to_json_with_provenance`
        // helper, which is also the source of truth for the
        // approve-scripts JSON emitter. Both sides cannot drift on
        // the entry shape.
        //
        // `version_diff` is `null` when no prior binding for the
        // package name exists (first-time review). When a prior
        // exists, the structured object is documented on
        // `version_diff::version_diff_to_json`.
        //
        // The per-package `provenance.verified` block emits when
        // the drift gate captured a `ProvenanceStatus` for this
        // `(name, version)` pair. Sparse — only packages with a
        // rich-form `trustedDependencies` binding triggered a
        // fetch.
        let trusted_for_json = read_trusted_deps_from_manifest(project_dir).unwrap_or_default();
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    crate::version_diff::blocked_to_json_with_provenance(
                        bp,
                        &trusted_for_json,
                        Some(install_provenance_status_map),
                    )
                })
                .collect(),
        );
        if !blocked_capture.state.blocked_packages.is_empty() {
            json["next_steps"] = crate::json_contract::command_next_steps(
                "Review blocked lifecycle scripts",
                "lpm approve-scripts",
            );
        }
        if let Some(counts) = audit_summary_for_envelope {
            json["audit_summary"] = serde_json::to_value(counts).unwrap_or(serde_json::Value::Null);
        }
        crate::security_floor::attach_security_posture(&mut json, force_security_floor);
        report_capture::emit_install_json(&json);
    } else {
        // print the override apply summary BEFORE
        // the success line so it doesn't get lost at the bottom of the
        // output. Only emit on the fresh-resolution path; the lockfile
        // fast path already had the summary printed during the
        // resolution that produced the lockfile, so re-emitting it
        // would be misleading ("Applied N overrides" implies we just
        // applied them).
        if !applied_overrides.is_empty() {
            println!();
            output::info_line(crate::install_ui::terminal_line!(
                "Applied {} override{}:",
                install_ui::bold(&applied_overrides.len().to_string()),
                if applied_overrides.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for hit in applied_overrides {
                let source_ref = hit.source_display();
                let line = match &hit.via_parent {
                    Some(parent) => crate::install_ui::terminal_line!(
                        "   {} {} → {} (via {}, reached through {})",
                        install_ui::bold(&hit.package),
                        install_ui::dim(&hit.from_version),
                        install_ui::bold(&hit.to_version),
                        &source_ref,
                        install_ui::bold(parent),
                    ),
                    None => crate::install_ui::terminal_line!(
                        "   {} {} → {} (via {})",
                        install_ui::bold(&hit.package),
                        install_ui::dim(&hit.from_version),
                        install_ui::bold(&hit.to_version),
                        &source_ref,
                    ),
                };
                println!("{line}");
            }
        }

        // summary of applied patches. Mirrors
        // the override summary above. **invariant :** filter
        // to entries that ACTUALLY did work this run (`touched_anything`)
        // so a no-op idempotent rerun doesn't print "Applied 1 patch"
        // with zero files. The patches are still in effect on disk
        // (the state file still records them), but if we did no work
        // we don't claim we did.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        if !applied_patches_summary.is_empty() {
            println!();
            output::info_line(crate::install_ui::terminal_line!(
                "Applied {} patch{}:",
                install_ui::bold(&applied_patches_summary.len().to_string()),
                if applied_patches_summary.len() == 1 {
                    ""
                } else {
                    "es"
                }
            ));
            for a in &applied_patches_summary {
                let rel_patch = a
                    .patch_path
                    .strip_prefix(project_dir)
                    .unwrap_or(&a.patch_path);
                let total = a.files_modified + a.files_added + a.files_deleted;
                println!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "   {}@{} ({}, {} file{})",
                        install_ui::bold(&a.name),
                        install_ui::dim(&a.version),
                        install_ui::dim(&rel_patch.display().to_string()),
                        total,
                        if total == 1 { "" } else { "s" },
                    )
                );
            }
        }

        // Diff direct deps against the pre-install lockfile snapshot.
        // Only deps whose resolved version CHANGED in this run land in
        // the `+ pkg@version` list — a no-op refresh prints no list,
        // `lpm i react` prints just `+ react@…`, and a hand-edited
        // manifest prints exactly the diff. The resolver's `is_direct`
        // flag scopes the diff to top-level deps so transitives never
        // pollute the list.
        //
        // Inlined silent variant of [`collect_direct_versions`]. The
        // canonical helper emits a `tracing::warn!` on duplicate
        // `is_direct = true` entries — useful as a diagnostic for the
        // `lpm i <pkg>` finalize path, but a latent resolver bug
        // occasionally double-marks deps like `chalk` / `ora` when
        // peer-rule auto-installs collide with their declared positions.
        // Surfacing that warning on every bare install of a typical
        // project would look broken. Silent last-wins instead.
        let post_direct_versions: HashMap<String, lpm_semver::Version> = packages
            .iter()
            .filter(|p| p.is_direct)
            .filter_map(|p| {
                lpm_semver::Version::parse(&p.version)
                    .ok()
                    .map(|v| (p.name.clone(), v))
            })
            .collect();
        let mut changed_direct: Vec<(String, String)> = Vec::new();
        for (name, post_v) in &post_direct_versions {
            let post_str = post_v.to_string();
            match pre_install_direct_versions.get(name) {
                Some(pre_v) if pre_v == &post_str => continue,
                _ => changed_direct.push((name.clone(), post_str)),
            }
        }
        changed_direct.sort();

        if !changed_direct.is_empty() {
            eprintln!();
            for (name, version) in &changed_direct {
                // Annotate with `(vX.Y.Z available)` when the
                // resolver's metadata cache has a stable release newer
                // than the version we just installed. Suppressed for:
                // * lockfile fast-path (no cache → empty map),
                // * non-registry sources (filtered out of `cache`),
                // * unparseable / equal / older latest versions.
                let hint = latest_stable_versions.get(name).and_then(|latest| {
                    let installed = lpm_semver::Version::parse(version).ok()?;
                    let candidate = lpm_semver::Version::parse(latest).ok()?;
                    (candidate > installed).then(|| format!("(v{latest} available)"))
                });
                install_ui::plus(name, version, hint.as_deref());
            }
        }

        // Verified-via-Sigstore counter. Drift gate populates this map
        // per package; `Verified` is the only state that earns the
        // green checkmark line. `Unverified` (operator-skipped) and
        // entries absent from the map are not counted — we only assert
        // the strong signal here, never inflate it.
        let verified_count = install_provenance_status_map
            .values()
            .filter(|s| matches!(s, lpm_common::ProvenanceStatus::Verified(_)))
            .count();

        let reported_count = if is_add_invocation {
            changed_direct.len()
        } else {
            packages.len()
        };
        let action = if is_add_invocation {
            "added"
        } else {
            "installed"
        };
        let duration_str = install_ui::format_duration(elapsed);
        let pkg_word = install_ui::packages_word(reported_count);
        eprintln!();
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · {} {} {} in {}",
            action,
            install_ui::bold(&reported_count.to_string()),
            pkg_word,
            install_ui::green(&duration_str),
        ));
        if verified_count > 0 {
            install_ui::done_untrusted(&format!(
                "{verified_count} of {} {} verified via Sigstore",
                packages.len(),
                install_ui::packages_word(packages.len()),
            ));
        }

        // Audit-after-install advisory. Yellow `!` line; vulnerability
        // count goes red when non-zero. Computed above before the
        // human/JSON branch split so both surfaces agree.
        if let Some(counts) = audit_summary_for_envelope {
            install_ui::warn_line(install_ui::format_audit_advisory(
                counts.packages_audited,
                counts.vulnerabilities,
                counts.suspicious,
                counts.elapsed_ms,
            ));
        }

        if verbose {
            eprintln!(
                "  {}",
                format!("resolve: {resolve_ms}ms  fetch: {fetch_ms}ms  link: {link_ms}ms").dimmed()
            );
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map_or(0, |m| m.len());
            let lockfile_pkg_count = workspace_lockfile::read(lockfile_path)
                .map_or(packages.len(), |lf| lf.packages.len());
            eprintln!(
                "  {}",
                format!(
                    "lpm.lock ({lockfile_pkg_count} {}) + lpm.lockb ({})",
                    install_ui::packages_word(lockfile_pkg_count),
                    lpm_common::format_bytes(lockb_size),
                )
                .dimmed()
            );
            eprintln!(
                "  {}",
                format!(
                    "{} linked, {} symlinked",
                    link_result.linked, link_result.symlinked,
                )
                .dimmed()
            );
        }
    }
}
