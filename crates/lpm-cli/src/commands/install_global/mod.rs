//! `lpm install -g <pkg>` — persistent global install pipeline.
//!
//! Three-phase crash-safe transaction:
//!
//! 1. Pre-resolve via registry (no lock) — pick a concrete version,
//!    integrity, source. [`save_spec`] decides what
//!    `saved_spec` to persist. Then **acquire `.tx.lock`**, write
//!    INTENT to WAL, write `[pending.<pkg>]` to manifest with empty
//!    `commands` (the install pipeline discovers commands at step 2),
//!    release lock.
//! 2. Slow work, no global tx lock held. A tx-local in-flight lock
//!    prevents startup recovery from treating this live install as
//!    orphaned while still allowing unrelated global installs to
//!    overlap their fetch/link phases. Self-hosted install via
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
//! Fresh-install, upgrade, collision resolution, and approve-scripts
//! capture are all supported (WAL-backed, crash-safe).

mod collision_ux;
mod commit;
mod display;
mod inner;
mod prepare;
mod resolve;
mod rollback;

pub use collision_ux::CollisionResolution;
pub use inner::InstallGlobalOverrides;

use super::global_util::{discover_materialized_bin_commands, mk_tx_id};
use crate::output;
use collision_ux::maybe_prompt_for_collisions;
use commit::commit_locked;
use display::{emit_post_install_blocked_warning, print_success};
use inner::do_install;
use lpm_common::color::Painted;
use lpm_common::{
    LpmError, LpmRoot, sanitize_for_terminal, with_exclusive_lock, with_exclusive_lock_async,
};
use lpm_global::{InstallReadyMarker, write_marker};
use lpm_registry::RegistryClient;
use prepare::prepare_locked;
use resolve::pre_resolve;
use rollback::rollback_after_install_failure;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    spec: &str,
    resolution: CollisionResolution,
    json_output: bool,
    overrides: InstallGlobalOverrides,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    crate::security_approval::ensure_global_trust_authorized(
        &root,
        json_output,
        crate::security_approval::ApprovalSource::GlobalConfig,
    )?;
    // Use the injected client so registry flags and session config
    // propagate into the inner project-shaped install.
    let registry = client.clone_with_config();
    let release_age_policy =
        crate::release_age_selection::resolver_policy_for_project_with_excludes(
            &root.global_root(),
            overrides.min_release_age_override,
            &overrides.min_release_age_exclude,
            overrides.allow_new,
            json_output,
        )?;

    // ─── Pre-resolve (no lock) ─────────────────────────────────────
    let resolved = pre_resolve(&registry, spec, &release_age_policy).await?;
    if !json_output {
        let name_safe = sanitize_for_terminal(&resolved.name);
        let version_safe = sanitize_for_terminal(&resolved.version.to_string());
        output::info(&format!(
            "{} resolved to {}",
            name_safe.bold(),
            version_safe.dimmed()
        ));
    }

    let tx_id = mk_tx_id();
    let inflight_lock = lpm_global::inflight_tx_lock(&root, &tx_id);
    with_exclusive_lock_async(inflight_lock, async {
        // ─── Step 1: prepare under .tx.lock ────────────────────────────
        let prep = with_exclusive_lock(root.global_tx_lock(), || {
            prepare_locked(&root, &resolved, tx_id)
        })?;

        // ─── Step 2: slow install (no global tx lock) ──────────────────
        if !json_output {
            let spec_safe = sanitize_for_terminal(spec);
            output::info(&format!("installing {}...", spec_safe.bold()));
        }
        // Step 2 failures (network, resolution, extract, link) are
        // intentionally NOT cleaned up here: recovery's roll-back path on
        // the next `lpm` invocation sees the uncompleted INTENT,
        // validate_install_root returns MissingMarker, and roll-back
        // removes the pending row + cleans the install root. Single
        // cleanup code path, called from one place.
        do_install(&root, &registry, &prep, json_output, &overrides).await?;
        let commands = match discover_materialized_bin_commands(&prep.install_root, &prep.name) {
            Ok(commands) => commands,
            Err(e) => {
                rollback_after_install_failure(&root, &prep, &e.to_string())?;
                return Err(e);
            }
        };
        if commands.is_empty() {
            let name_safe = sanitize_for_terminal(&prep.name);
            let reason = format!(
                "package '{name_safe}' exposes no bin entries — `lpm install -g` is for executable tools. \
                 Install it as a project dep with `lpm install {name_safe}` and `require()`/`import` it."
            );
            rollback_after_install_failure(&root, &prep, &reason)?;
            return Err(LpmError::Script(reason));
        }
        let marker = InstallReadyMarker::new(commands);
        if let Err(e) = write_marker(&prep.install_root, &marker) {
            rollback_after_install_failure(&root, &prep, &e.to_string())?;
            return Err(e);
        }

        // ─── Step 3a: TTY interactive prompt ───────────────────
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
        // resolution uses marker_commands as the authority. The resolution
        // is validated AGAINST marker_commands inside the lock (not
        // earlier), since only the marker is the
        // authoritative post-extract command set.
        let active = with_exclusive_lock(root.global_tx_lock(), || {
            commit_locked(&root, &prep, &resolution)
        })?;

        // ─── Step 4: opportunistic tombstone sweep ─────────────
        // Fresh installs rarely tombstone (the rollback branch does),
        // but running a sweep post-commit means any leftover tombstones
        // from a prior failed tx get cleared as part of the happy path —
        // users don't have to remember to `lpm cache prune --apply`.
        //
        // `try_*` (non-blocking): another global command may be running in
        // parallel; we'd rather move on than wait. Errors are logged and
        // swallowed — the tx already committed, and the sweep retries on
        // next run.
        crate::commands::global::run_opportunistic_sweep(&root);

        // ─── Step 5: PATH onboarding hint ──────────────────────
        // Idempotent: at most one banner per host. The helper handles
        // marker stickiness and JSON-mode silence internally; we just
        // call it post-success and pass the report into print_success
        // so JSON consumers can see it as structured data.
        let hint = crate::path_onboarding::maybe_show_path_hint(&root, json_output);

        // ─── Output ────────────────────────────────────────────────────
        print_success(&active, &hint, json_output);

        // ─── Step 6: post-install blocked-scripts warning ──────
        // Mirrors the project-level post-install security summary
        // (suppressed inside the inner pipeline via `no_security_summary:
        // true`). Emits AFTER print_success so the happy-path "Installed
        // eslint@9.24.0" line lands first, then points at
        // `lpm approve-scripts --global`.
        emit_post_install_blocked_warning(&root, &prep, json_output);

        Ok(())
    })
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_global::PackageSource;
    use lpm_registry::RegistryClient;
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
                    // This test asserts v1 store-pipeline interactions
                    // such as tarball fetch counts and wrapper layout.
                    ("LPM_STORE_VERSION", "v1".into()),
                ]),
            }
        }
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
            engines: Default::default(),
            dependencies: dependencies
                .iter()
                .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
                .collect(),
            dist: Some(lpm_registry::DistInfo {
                tarball: Some(tarball_url),
                integrity: Some(integrity),
                shasum: None,
                ..Default::default()
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
            modified: None,
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

        // `install_global::run` drives the orchestration in
        // `install.rs::run_with_options`, which builds a `BfsWalker` that
        // reads `RouteMode::from_env_or_default()`. Default in the
        // shipped binary is `Direct` — the walker hits `npm_registry_url`
        // for npm packages, not `base_url/api/registry/{name}`. We mount
        // each per-package metadata response at BOTH the proxy path and
        // the npm-direct path, and point `npm_registry_url` at the same
        // mock so the test is mode-agnostic: Direct hits `/cypress` on
        // the mock, Proxy hits `/api/registry/cypress`, either way the
        // same response lands.
        //
        // We drop the `.expect(1)` counts on individual GETs — the
        // walker may or may not issue a per-package GET depending on
        // the shared-cache + batch-metadata interplay. The install's
        // correctness is asserted by the `run(...)` return + manifest
        // shape below, not by a specific per-mock call count.
        let per_package = [
            ("cypress", &cypress_metadata),
            ("@cypress/xvfb", &xvfb_metadata),
            ("debug", &debug_metadata),
            ("chalk", &chalk_metadata),
            ("supports-color", &supports_color_metadata),
        ];
        for (name, metadata) in per_package {
            // LPM proxy path (Proxy mode).
            Mock::given(method("GET"))
                .and(match_path(format!("/api/registry/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
                .mount(&server)
                .await;
            // npm-direct path (Direct mode, the shipped default).
            Mock::given(method("GET"))
                .and(match_path(format!("/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
                .mount(&server)
                .await;
        }

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
            .mount(&server)
            .await;

        run(
            &RegistryClient::new()
                .with_base_url(server.uri())
                .with_npm_registry_url(server.uri()),
            "cypress@15.13.1",
            CollisionResolution::default(),
            true,
            InstallGlobalOverrides::default(),
        )
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
}
