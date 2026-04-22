//! macOS Seatbelt backend: routes `Sandbox::spawn` through
//! `sandbox-exec -p <profile> <program> <args...>`. Phase 46 P5
//! Chunk 2.
//!
//! One `sandbox-exec` invocation per script. The profile is
//! synthesized at [`SeatbeltSandbox::new`] so profile-render errors
//! surface before the spawn attempt, and so the per-spawn cost is
//! just process startup (not string building).
//!
//! **Mode coverage:**
//! - [`SandboxMode::Enforce`] (Chunk 2): standard sandbox-exec
//!   deny-default profile from [`seatbelt::render_profile`].
//! - [`SandboxMode::LogOnly`] (Chunk 4): permissive profile from
//!   [`seatbelt::render_logonly_profile`]. Opens with
//!   `(allow (with report) default)`, then layers the Enforce allow
//!   list after it — under SBPL last-match-wins, Enforce-covered
//!   operations are silent allows and everything else falls through
//!   to the permissive+report fallback. Reports flow through
//!   `sandboxd` and are viewable via `log show --predicate
//!   'senderImagePath CONTAINS "Sandbox"'`. This is Apple's own
//!   internal observe-only idiom; the `(deny default)` + `(with
//!   report)` combination was empirically unavailable (`sandbox-exec:
//!   report modifier does not apply to deny action`).
//! - [`SandboxMode::Disabled`]: never reaches this module — routed
//!   to [`crate::NoopSandbox`] by the factory. Defensive error in
//!   [`SeatbeltSandbox::new`] catches factory regressions rather
//!   than silently picking a profile variant.

#![cfg(target_os = "macos")]

use crate::seatbelt;
use crate::{Sandbox, SandboxError, SandboxMode, SandboxSpec, SandboxedCommand};

pub(crate) struct SeatbeltSandbox {
    profile: String,
    mode: SandboxMode,
    #[allow(dead_code)] // Kept for structured diagnostics in Chunk 4
    spec: SandboxSpec,
}

impl SeatbeltSandbox {
    pub(crate) fn new(spec: SandboxSpec, mode: SandboxMode) -> Result<Self, SandboxError> {
        let profile = match mode {
            SandboxMode::Enforce => seatbelt::render_profile(&spec)?,
            SandboxMode::LogOnly => seatbelt::render_logonly_profile(&spec)?,
            // Disabled never reaches this backend — the factory in
            // [`crate::new_for_platform`] short-circuits to
            // [`crate::NoopSandbox`] before dispatching. Defend with
            // an explicit error rather than rendering an undefined
            // profile variant.
            SandboxMode::Disabled => {
                return Err(SandboxError::InvalidSpec {
                    reason: "SandboxMode::Disabled reached SeatbeltSandbox — should \
                             have been routed to NoopSandbox by the factory"
                        .to_string(),
                });
            }
        };
        Ok(Self {
            profile,
            mode,
            spec,
        })
    }
}

impl Sandbox for SeatbeltSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<std::process::Child, SandboxError> {
        // `sandbox-exec -p <profile> <program> <args...>` runs the
        // child under the named profile. `-p` takes the profile body
        // inline, so no temp-file handoff is needed. Env, cwd, and
        // stdio apply to the sandbox-exec process — it inherits them
        // to the ultimate child.
        let mut command = std::process::Command::new("sandbox-exec");
        command.arg("-p").arg(&self.profile);
        command.arg(&cmd.program);
        for a in &cmd.args {
            command.arg(a);
        }

        if cmd.env_clear {
            command.env_clear();
        }
        for (k, v) in &cmd.envs {
            command.env(k, v);
        }
        if let Some(dir) = &cmd.current_dir {
            command.current_dir(dir);
        }
        command.stdout(std::process::Stdio::from(cmd.stdout));
        command.stderr(std::process::Stdio::from(cmd.stderr));
        command.stdin(std::process::Stdio::from(cmd.stdin));

        // Put the sandbox-exec process (and its descendants) in their
        // own process group so the caller's timeout path can kill
        // the whole tree with `kill(-pid, SIGKILL)`. Matches the
        // pre-Phase-46 build.rs behavior.
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        command.spawn().map_err(|e| SandboxError::SpawnFailed {
            reason: format!("sandbox-exec spawn failed: {e}"),
        })
    }

    fn backend_name(&self) -> &'static str {
        "seatbelt"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxMode, SandboxStdio, new_for_platform};
    use std::path::PathBuf;

    fn realistic_spec() -> SandboxSpec {
        let home = dirs::home_dir().expect("home dir for test");
        let tmp = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        // package_dir doesn't need to exist for profile rendering;
        // real integration tests (tests/seatbelt_integration.rs) use
        // a real tempdir.
        SandboxSpec {
            package_dir: home.join(".lpm/store/testpkg@0.1.0"),
            project_dir: home.join("lpm-sandbox-test-project"),
            package_name: "testpkg".into(),
            package_version: "0.1.0".into(),
            store_root: home.join(".lpm/store"),
            home_dir: home,
            tmpdir: tmp,
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn new_renders_profile_successfully_for_realistic_spec() {
        let sb = SeatbeltSandbox::new(realistic_spec(), SandboxMode::Enforce).unwrap();
        assert!(sb.profile.contains("(deny default)"));
        assert!(sb.profile.contains("(allow network*)"));
    }

    #[test]
    fn backend_name_is_seatbelt() {
        let sb = SeatbeltSandbox::new(realistic_spec(), SandboxMode::Enforce).unwrap();
        assert_eq!(sb.backend_name(), "seatbelt");
    }

    #[test]
    fn mode_round_trips() {
        for m in [SandboxMode::Enforce, SandboxMode::LogOnly] {
            let sb = SeatbeltSandbox::new(realistic_spec(), m).unwrap();
            assert_eq!(sb.mode(), m);
        }
    }

    #[test]
    fn spawns_a_trivial_benign_command_inside_its_own_package_dir() {
        // Runs `true` under the sandbox — no filesystem access needed,
        // should succeed. Asserts that profile + sandbox-exec path is
        // wired end-to-end.
        let spec = realistic_spec();
        let sb = new_for_platform(spec, SandboxMode::Enforce).unwrap();
        let cmd = SandboxedCommand::new("/usr/bin/true").envs_cleared([("PATH", "/usr/bin:/bin")]);
        let mut child = sb.spawn(cmd).expect("spawn under enforce");
        let status = child.wait().expect("wait");
        assert!(status.success(), "/usr/bin/true under sandbox must exit 0");
    }

    #[test]
    fn enforces_deny_default_for_forbidden_read() {
        // §11 P5 ship criterion #1 (partial — full corpus is in
        // Chunk 5). Creates a real file inside a tempdir that is NOT
        // in the sandbox's allow list, then attempts to `cat` it.
        // Seatbelt must deny the read — the deny-default + allow-
        // list combination from §9.3 leaves that path unreferenced.
        let td = tempfile::tempdir().unwrap();
        let secret = td.path().join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET").unwrap();

        let home = dirs::home_dir().expect("home dir");
        let spec = SandboxSpec {
            package_dir: home.join(".lpm/store/probe@0.1.0"),
            project_dir: home.join("lpm-sandbox-test-project"),
            package_name: "probe".into(),
            package_version: "0.1.0".into(),
            store_root: home.join(".lpm/store"),
            home_dir: home.clone(),
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = new_for_platform(spec, SandboxMode::Enforce).unwrap();

        let mut cmd = SandboxedCommand::new("/bin/cat")
            .arg(&secret)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            !status.success(),
            "Seatbelt must deny reading a path outside the allow list — got status {status:?}"
        );
    }

    #[test]
    fn allows_write_into_package_dir_under_enforce() {
        let td = tempfile::tempdir().unwrap();
        let pkg_dir = td.path().join("store").join("pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let project_dir = td.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let home = dirs::home_dir().expect("home dir");

        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: td.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = new_for_platform(spec, SandboxMode::Enforce).unwrap();

        let mut cmd = SandboxedCommand::new("/bin/sh")
            .arg("-c")
            .arg("echo hi > marker")
            .current_dir(&pkg_dir)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "write to package_dir under Enforce must succeed, got {status:?}"
        );
        assert!(pkg_dir.join("marker").exists());
    }

    #[test]
    fn denies_write_outside_allow_list_under_enforce() {
        // Second half of ship criterion #1: a write into a path
        // outside the allow list must be blocked. Chose /tmp/<uuid>/...
        // that's not inside any package_dir/project_dir/cache; /tmp
        // IS in the write allow-list, so we use a sibling of /tmp
        // under $HOME that is read-allowed but not write-allowed.
        let td = tempfile::tempdir().unwrap();
        let pkg_dir = td.path().join("store").join("pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let project_dir = td.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let forbidden_write_target = td.path().join("outside.txt");

        let home = dirs::home_dir().expect("home dir");
        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: td.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = new_for_platform(spec, SandboxMode::Enforce).unwrap();

        let mut cmd = SandboxedCommand::new("/bin/sh")
            .arg("-c")
            .arg(format!("echo leak > {}", forbidden_write_target.display()))
            .current_dir(&pkg_dir)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            !status.success(),
            "Seatbelt must deny writing outside the allow list — got status {status:?}"
        );
        assert!(
            !forbidden_write_target.exists(),
            "sandbox escape — forbidden file was created"
        );
    }

    #[test]
    fn logonly_permits_write_that_enforce_would_deny() {
        // Core LogOnly contract: a write into a path outside the
        // Enforce allow list SUCCEEDS (permissive fallback via
        // `(allow (with report) default)`) rather than being blocked.
        // The denials-in-Enforce are visible via `log show` but
        // asserting log-subsystem content cross-machine is flaky; the
        // "didn't block" half is the sufficient contract assertion.
        // Users still see the `--sandbox-log` banner warning that a
        // clean run is NOT a safety signal (build.rs enforces that
        // message).
        let td = tempfile::tempdir().unwrap();
        let pkg_dir = td.path().join("store").join("pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let project_dir = td.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let forbidden_write_target = td.path().join("outside.txt");

        let home = dirs::home_dir().expect("home");
        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: td.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = new_for_platform(spec, SandboxMode::LogOnly).unwrap();

        let mut cmd = SandboxedCommand::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "echo reported > {}",
                forbidden_write_target.display()
            ))
            .current_dir(&pkg_dir)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "LogOnly must NOT block writes outside the allow list — \
             status {status:?}. If this fails, the (allow (with report) \
             default) fallback isn't in the profile or SBPL last-match-wins \
             is behaving differently than expected."
        );
        assert!(
            forbidden_write_target.exists(),
            "LogOnly write into a forbidden-in-Enforce path must succeed"
        );
    }

    #[test]
    fn logonly_still_allows_package_dir_writes_silently() {
        // Same package-dir write that succeeds under Enforce also
        // succeeds under LogOnly. The Enforce rules override the
        // permissive fallback for covered paths (SBPL last-match-wins),
        // so covered writes are silent allows — identical to Enforce.
        let td = tempfile::tempdir().unwrap();
        let pkg_dir = td.path().join("store").join("pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let project_dir = td.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let home = dirs::home_dir().expect("home");

        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: td.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = new_for_platform(spec, SandboxMode::LogOnly).unwrap();

        let mut cmd = SandboxedCommand::new("/bin/sh")
            .arg("-c")
            .arg("echo silent > marker")
            .current_dir(&pkg_dir)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(status.success());
        assert!(pkg_dir.join("marker").exists());
    }

    #[test]
    fn mode_round_trips_for_logonly() {
        let sb = SeatbeltSandbox::new(realistic_spec(), SandboxMode::LogOnly).unwrap();
        assert_eq!(sb.mode(), SandboxMode::LogOnly);
        assert_eq!(sb.backend_name(), "seatbelt");
    }

    #[test]
    fn new_rejects_disabled_mode_defensively() {
        // Disabled should never reach here — the factory routes it
        // to NoopSandbox. Defend against future factory bugs with
        // an explicit error rather than silently picking a variant.
        match SeatbeltSandbox::new(realistic_spec(), SandboxMode::Disabled) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("Disabled"));
                assert!(reason.contains("NoopSandbox"));
            }
            Ok(_) => panic!("Disabled mode must be rejected by SeatbeltSandbox::new"),
            Err(other) => panic!("expected InvalidSpec, got {other:?}"),
        }
    }
}
