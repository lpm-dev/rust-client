/// Build a complete install root the upgrade commit will accept:
/// a `node_modules/.bin/<cmd>` for every command and a valid marker.
#[cfg(unix)]
pub(super) fn make_complete_install_root(install_root: &std::path::Path, commands: &[&str]) {
    let bin = install_root.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin).unwrap();
    for cmd in commands {
        let target = bin.join(cmd);
        std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    std::fs::write(
        install_root.join("lpm.lock"),
        lpm_global::MINIMAL_VALID_LOCKFILE_TOML,
    )
    .unwrap();
    lpm_global::write_marker(
        install_root,
        &lpm_global::InstallReadyMarker::new(commands.iter().map(|c| c.to_string()).collect()),
    )
    .unwrap();
}

#[cfg(unix)]
pub(super) fn pre_upgrade_manifest_with_alias(
    root_dir: &str,
    commands: &[&str],
    alias_key: &str,
    alias_bin: &str,
) -> lpm_global::GlobalManifest {
    let mut manifest = lpm_global::GlobalManifest::default();
    manifest.packages.insert(
        "foo".into(),
        lpm_global::PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-old".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: root_dir.into(),
            // commands excludes the aliased-away bin per the
            // manifest invariant.
            commands: commands
                .iter()
                .filter(|c| **c != alias_bin)
                .map(|c| c.to_string())
                .collect(),
        },
    );
    manifest.aliases.insert(
        alias_key.into(),
        lpm_global::AliasEntry {
            package: "foo".into(),
            bin: alias_bin.into(),
        },
    );
    manifest
}
