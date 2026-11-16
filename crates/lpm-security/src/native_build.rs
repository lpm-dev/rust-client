//! The native build a package gets without naming it.

use std::path::Path;

/// What npm, pnpm, yarn and bun run as a package's `install` script when
/// its manifest names none and it ships a `binding.gyp`.
pub const IMPLIED_INSTALL_SCRIPT: &str = "node-gyp rebuild";

/// The `install` script the package at `package_dir` gets without naming
/// one: [`IMPLIED_INSTALL_SCRIPT`] for a package with a `binding.gyp` file
/// at its root, unless its manifest names an `install` or a `preinstall`
/// script or sets `gypfile` to `false`. Matches npm's rule, which the
/// registry applies too when it reports such a package as having an
/// install script.
pub fn implied_install_script(
    package_dir: &Path,
    manifest: &serde_json::Map<String, serde_json::Value>,
) -> Option<&'static str> {
    (leaves_install_to_binding_gyp(manifest) && has_binding_gyp(package_dir))
        .then_some(IMPLIED_INSTALL_SCRIPT)
}

/// Whether a [`BINDING_GYP`] file sits at the root of `package_dir`.
pub fn has_binding_gyp(package_dir: &Path) -> bool {
    std::fs::symlink_metadata(package_dir.join(BINDING_GYP))
        .is_ok_and(|metadata| metadata.is_file())
}

/// The file at a package's root that implies its native build.
pub const BINDING_GYP: &str = "binding.gyp";

/// Whether `manifest` leaves the `install` script to a [`BINDING_GYP`]
/// beside it: it names no `install` and no `preinstall` script and doesn't
/// set `gypfile` to `false`. For a caller that looks for the file itself.
pub fn leaves_install_to_binding_gyp(
    manifest: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let script = |phase: &str| {
        manifest
            .get("scripts")
            .and_then(|scripts| scripts.get(phase))
            .and_then(serde_json::Value::as_str)
    };
    scripts_leave_install_to_binding_gyp(
        script("install"),
        script("preinstall"),
        manifest.get("gypfile").and_then(serde_json::Value::as_bool),
    )
}

/// [`leaves_install_to_binding_gyp`] for a manifest already read into its
/// `install` and `preinstall` scripts and its `gypfile` setting.
pub fn scripts_leave_install_to_binding_gyp(
    install: Option<&str>,
    preinstall: Option<&str>,
    gypfile: Option<bool>,
) -> bool {
    let names = |script: Option<&str>| script.is_some_and(|body| !body.is_empty());
    !names(install) && !names(preinstall) && gypfile != Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn implied(manifest: serde_json::Value, binding_gyp: bool) -> Option<&'static str> {
        let package = tempfile::tempdir().unwrap();
        if binding_gyp {
            std::fs::write(package.path().join("binding.gyp"), "{}").unwrap();
        }
        implied_install_script(package.path(), manifest.as_object().unwrap())
    }

    #[test]
    fn a_binding_gyp_without_an_install_script_implies_the_native_build() {
        for manifest in [
            serde_json::json!({}),
            serde_json::json!({ "scripts": { "test": "node test.js" } }),
            serde_json::json!({ "scripts": { "postinstall": "node post.js" } }),
            serde_json::json!({ "scripts": { "install": "" }, "gypfile": true }),
        ] {
            assert_eq!(
                implied(manifest.clone(), true),
                Some("node-gyp rebuild"),
                "{manifest}"
            );
        }
    }

    #[test]
    fn a_named_install_or_preinstall_script_or_gypfile_false_implies_nothing() {
        for manifest in [
            serde_json::json!({ "scripts": { "install": "node-gyp-build" } }),
            serde_json::json!({ "scripts": { "preinstall": "node pre.js" } }),
            serde_json::json!({ "gypfile": false }),
        ] {
            assert_eq!(implied(manifest.clone(), true), None, "{manifest}");
        }
    }

    #[test]
    fn a_package_without_a_binding_gyp_file_implies_nothing() {
        assert_eq!(implied(serde_json::json!({}), false), None);

        let package = tempfile::tempdir().unwrap();
        std::fs::create_dir(package.path().join("binding.gyp")).unwrap();
        assert_eq!(
            implied_install_script(package.path(), &serde_json::Map::new()),
            None
        );
    }
}
