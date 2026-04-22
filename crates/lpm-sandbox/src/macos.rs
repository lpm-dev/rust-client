//! macOS Seatbelt backend: routes `Sandbox::spawn` through
//! `sandbox-exec -p <profile> <program> <args...>`. Phase 46 P5
//! Chunk 2.
//!
//! One `sandbox-exec` invocation per script. The profile is
//! synthesized at [`SeatbeltSandbox::new`] so profile-render errors
//! surface before the spawn attempt, and so the per-spawn cost is
//! just process startup (not string building).
//!
//! **Mode coverage in Chunk 2:** only [`SandboxMode::Enforce`] has
//! a non-trivial implementation here. [`SandboxMode::Disabled`] is
//! handled one layer up by [`crate::NoopSandbox`] and never reaches
//! this module. [`SandboxMode::LogOnly`] is reserved but currently
//! rejected at the CLI layer (see the `--sandbox-log` handler in
//! `lpm-cli`'s `main.rs`) — Chunk 4 lands the real non-enforcing
//! diagnostic path (likely via parallel DTrace instrumentation
//! rather than any sandbox-exec primitive, since Seatbelt has no
//! "compile and log but don't enforce" mode). Until then this
//! backend enforces under any non-Disabled mode; the CLI-level
//! rejection is what preserves the contract that a clean
//! `--sandbox-log` run is never a safety signal.

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
        let profile = seatbelt::render_profile(&spec)?;
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
}
