//! Path+access rule description for the Linux landlock backend.
//!
//! Deliberately platform-neutral so it can be unit-tested on macOS
//! host (the CI Linux target exercises the real landlock install).
//! The landlock-specific bits — ABI negotiation, `PathFd` open, rule
//! install, `restrict_self` — live in [`crate::linux`].
//!
//! Rule layout mirrors §9.3 of the Phase 46 plan exactly:
//! - Reads broad (project + toolchain + system).
//! - Writes narrow (package store dir + `node_modules` + `.husky` +
//!   `.lpm` + known caches + temp + extras from `sandboxWriteDirs`).
//! - No blanket home-dir read — `~/.ssh`, `~/.aws`, `~/.config/**`
//!   outside `~/.cache`/`~/.node-gyp`/`~/.npm` stay denied by default.
//!
//! Landlock semantics: rules are **additive** (union of access bits).
//! A path that falls under both a Read rule and a ReadWrite rule ends
//! up ReadWrite. That's why `project_dir` gets a Read rule and
//! `project_dir/node_modules` gets a ReadWrite rule — the write rule
//! wins where they overlap, and the read rule still grants read
//! access to the rest of `project_dir`.

use crate::SandboxSpec;
use std::path::PathBuf;

/// Access level a landlock rule grants for a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleAccess {
    /// Read-only: `ReadFile` + `ReadDir` (in landlock terms). Covers
    /// open-for-read, stat, readdir, and readlink on symlinks under
    /// the path.
    Read,
    /// Full access: read + create + remove + write. The full
    /// `AccessFs::from_all(abi)` set for the negotiated ABI.
    ReadWrite,
}

/// Read-only system paths every reasonable Linux lifecycle script
/// needs. Listed in a const so the rules-layer contract is visible
/// from one place. Chunk 5's escape corpus asserts these stay
/// narrow (e.g. no `/root`, no `/`).
pub(crate) const SYSTEM_READ_PATHS: &[&str] = &[
    // Binaries, libraries, and the dynamic linker. On usr-merged
    // distros `/bin` and `/sbin` are symlinks to `/usr/bin` and
    // `/usr/sbin`, but landlock follows them so rules stay correct.
    "/usr", "/bin", "/sbin", "/lib", "/lib64",
    // Locale, resolver, `ld.so.conf`, `ld.so.cache`, timezone,
    // ca-certificates — the "system configuration" reads libc and
    // network scripts expect.
    "/etc",
    // `/proc/self/*`, `/proc/cpuinfo`, `/proc/sys/kernel/*`: needed
    // by node's process module, by `uname -r`, and by tools that
    // probe their own PID. Landlock does NOT restrict procfs
    // beyond pathname enforcement, which is what we want.
    "/proc",
    // `/dev/null`, `/dev/urandom`, `/dev/tty`, `/dev/fd/*`,
    // `/dev/std{in,out,err}`. Narrower than the Seatbelt profile
    // because landlock doesn't expose iokit-style device classes;
    // containment on raw block devices is enforced at the unix
    // permission layer instead, which is adequate for the script
    // runner's threat model.
    "/dev",
];

/// Describe the full rule set for a given [`SandboxSpec`]. Order is
/// deterministic — tests pin on it indirectly (e.g. "first read rule
/// is package_dir") for regression catches.
///
/// Returns `Vec<(PathBuf, RuleAccess)>` instead of real
/// `landlock::PathBeneath` values so the function is:
/// 1. Testable without a Linux kernel (runs on macOS host).
/// 2. Free of unsafe `PathFd` opens at rule-description time (those
///    happen in the child's pre_exec hook in [`crate::linux`]).
pub(crate) fn describe_rules(spec: &SandboxSpec) -> Vec<(PathBuf, RuleAccess)> {
    let mut rules = Vec::with_capacity(32 + spec.extra_write_dirs.len());

    // Read-only system baseline.
    for p in SYSTEM_READ_PATHS {
        rules.push((PathBuf::from(p), RuleAccess::Read));
    }

    // Read-only project baseline. The package's own hoisted deps
    // under `{project}/node_modules/.lpm/` are reachable via this
    // rule under LPM's default linker strategy (clonefile on macOS,
    // hardlink on Linux — both place hoisted-dep content inside
    // the project tree, so rule matches path-locally). The
    // fallback symlink path would cross into `~/.lpm/store/` which
    // this rule doesn't cover; per Phase 46 D23, that's an
    // accepted corner — widening to `store_root` would expose
    // every other package the user has installed. If the fallback
    // path becomes common in practice, §9.7 documents the two
    // remediations (switch to hardlink, or widen reads).
    rules.push((spec.project_dir.clone(), RuleAccess::Read));
    // NVM-installed toolchain, per §9.3. Only added if the host has
    // a matching dir — [`crate::linux::spawn`] filters missing paths
    // at FD-open time; the description layer stays complete.
    let nvm = spec.home_dir.join(".nvm").join("versions");
    rules.push((nvm, RuleAccess::Read));

    // Read+write — the §9.3 narrow write list.
    rules.push((spec.package_dir.clone(), RuleAccess::ReadWrite));
    rules.push((spec.project_dir.join("node_modules"), RuleAccess::ReadWrite));
    rules.push((spec.project_dir.join(".husky"), RuleAccess::ReadWrite));
    rules.push((spec.project_dir.join(".lpm"), RuleAccess::ReadWrite));
    rules.push((spec.home_dir.join(".cache"), RuleAccess::ReadWrite));
    rules.push((spec.home_dir.join(".node-gyp"), RuleAccess::ReadWrite));
    rules.push((spec.home_dir.join(".npm"), RuleAccess::ReadWrite));
    rules.push((PathBuf::from("/tmp"), RuleAccess::ReadWrite));
    rules.push((spec.tmpdir.clone(), RuleAccess::ReadWrite));
    // `/dev/null` and `/dev/tty` as writable — shells redirect to
    // them constantly. The broader `/dev` Read rule already covers
    // reading these; the ReadWrite rule adds write bits. Union
    // semantics means the net effect is ReadWrite on the two
    // literals and Read on everything else under `/dev`.
    rules.push((PathBuf::from("/dev/null"), RuleAccess::ReadWrite));
    rules.push((PathBuf::from("/dev/tty"), RuleAccess::ReadWrite));

    // Per-project extras from `package.json > lpm > scripts >
    // sandboxWriteDirs`. Loader guarantees absolute paths.
    for p in &spec.extra_write_dirs {
        rules.push((p.clone(), RuleAccess::ReadWrite));
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> SandboxSpec {
        SandboxSpec {
            package_dir: PathBuf::from("/lpm-store/prisma@5.22.0"),
            project_dir: PathBuf::from("/home/u/proj"),
            package_name: "prisma".into(),
            package_version: "5.22.0".into(),
            store_root: PathBuf::from("/lpm-store"),
            home_dir: PathBuf::from("/home/u"),
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        }
    }

    fn contains_rule(rules: &[(PathBuf, RuleAccess)], path: &str, access: RuleAccess) -> bool {
        rules
            .iter()
            .any(|(p, a)| p.as_os_str() == path && *a == access)
    }

    #[test]
    fn package_dir_is_readwrite() {
        let rules = describe_rules(&spec());
        assert!(
            contains_rule(&rules, "/lpm-store/prisma@5.22.0", RuleAccess::ReadWrite),
            "package_dir must be RW so postinstall can write build artifacts: {rules:?}"
        );
    }

    #[test]
    fn project_dir_has_read_and_subpaths_have_write() {
        let rules = describe_rules(&spec());
        assert!(contains_rule(&rules, "/home/u/proj", RuleAccess::Read));
        assert!(contains_rule(
            &rules,
            "/home/u/proj/node_modules",
            RuleAccess::ReadWrite
        ));
        assert!(contains_rule(
            &rules,
            "/home/u/proj/.husky",
            RuleAccess::ReadWrite
        ));
        assert!(contains_rule(
            &rules,
            "/home/u/proj/.lpm",
            RuleAccess::ReadWrite
        ));
    }

    #[test]
    fn home_cache_paths_are_writable_but_home_itself_is_not() {
        let rules = describe_rules(&spec());
        assert!(contains_rule(
            &rules,
            "/home/u/.cache",
            RuleAccess::ReadWrite
        ));
        assert!(contains_rule(
            &rules,
            "/home/u/.node-gyp",
            RuleAccess::ReadWrite
        ));
        assert!(contains_rule(&rules, "/home/u/.npm", RuleAccess::ReadWrite));
        // No blanket $HOME rule — that would leak ~/.ssh, ~/.aws,
        // ~/.config/git etc.
        assert!(
            !rules.iter().any(|(p, _)| p.as_os_str() == "/home/u"),
            "home_dir itself must not appear in the rule set: {rules:?}"
        );
    }

    #[test]
    fn nvm_versions_is_read_only() {
        let rules = describe_rules(&spec());
        assert!(contains_rule(
            &rules,
            "/home/u/.nvm/versions",
            RuleAccess::Read
        ));
    }

    #[test]
    fn temp_paths_are_writable() {
        let rules = describe_rules(&spec());
        // `/tmp` is broadly writable by design — real-world
        // postinstalls shell out to `mktemp` and write intermediate
        // artifacts to `/tmp/...` paths (see compat_greens
        // `tmp_scratch_write_shape_succeeds`). `spec.tmpdir` on top
        // resolves to the same path on the default unit-test spec
        // (harmless union) but lets callers request a second narrow
        // scratch dir when they set TMPDIR elsewhere.
        assert!(contains_rule(&rules, "/tmp", RuleAccess::ReadWrite));
    }

    #[test]
    fn dev_null_and_dev_tty_are_writable_but_other_dev_is_read_only() {
        let rules = describe_rules(&spec());
        assert!(contains_rule(&rules, "/dev", RuleAccess::Read));
        assert!(contains_rule(&rules, "/dev/null", RuleAccess::ReadWrite));
        assert!(contains_rule(&rules, "/dev/tty", RuleAccess::ReadWrite));
        // No blanket /dev RW — additive semantics give us the right
        // union without it.
        assert!(
            !contains_rule(&rules, "/dev", RuleAccess::ReadWrite),
            "/dev must be Read-only; /dev/null + /dev/tty are the narrow RW exceptions"
        );
    }

    #[test]
    fn system_toolchain_paths_are_read_only() {
        let rules = describe_rules(&spec());
        for p in SYSTEM_READ_PATHS {
            assert!(
                contains_rule(&rules, p, RuleAccess::Read),
                "{p} must be readable"
            );
            // Never ReadWrite — system paths must never be writable
            // from a sandboxed script.
            assert!(
                !contains_rule(&rules, p, RuleAccess::ReadWrite),
                "{p} must NEVER be writable from the sandbox"
            );
        }
    }

    #[test]
    fn no_rule_covers_ssh_aws_or_root_home() {
        let rules = describe_rules(&spec());
        for (p, _) in &rules {
            let s = p.to_string_lossy();
            assert!(
                !s.contains("/.ssh"),
                "ssh must never be in the rule set: {s}"
            );
            assert!(
                !s.contains("/.aws"),
                "aws must never be in the rule set: {s}"
            );
            assert!(
                !s.starts_with("/root"),
                "root home must never be in the rule set: {s}"
            );
            // `/home/u` exactly (not the subpaths) was already
            // asserted-absent above; re-check here symmetric with
            // the ssh/aws guard.
            assert_ne!(p.as_os_str(), "/home/u");
        }
    }

    #[test]
    fn extra_write_dirs_are_readwrite_and_preserve_order() {
        let mut s = spec();
        s.extra_write_dirs = vec![
            PathBuf::from("/home/u/proj/build-output"),
            PathBuf::from("/home/u/.cache/ms-playwright"),
        ];
        let rules = describe_rules(&s);
        assert!(contains_rule(
            &rules,
            "/home/u/proj/build-output",
            RuleAccess::ReadWrite
        ));
        assert!(contains_rule(
            &rules,
            "/home/u/.cache/ms-playwright",
            RuleAccess::ReadWrite
        ));
        // The extras are appended at the end of the rule list so
        // trailing-order-dependent layers can rely on the invariant.
        let last = rules.last().unwrap();
        assert_eq!(last.0.as_os_str(), "/home/u/.cache/ms-playwright");
    }

    #[test]
    fn tmpdir_distinct_from_slash_tmp_gets_its_own_rule() {
        let mut s = spec();
        s.tmpdir = PathBuf::from("/var/tmp/user-xyz");
        let rules = describe_rules(&s);
        assert!(contains_rule(
            &rules,
            "/var/tmp/user-xyz",
            RuleAccess::ReadWrite
        ));
        assert!(contains_rule(&rules, "/tmp", RuleAccess::ReadWrite));
    }
}
