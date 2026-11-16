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
    let names = |phase: &str| {
        manifest
            .get("scripts")
            .and_then(|scripts| scripts.get(phase))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|body| !body.is_empty())
    };
    if names("install")
        || names("preinstall")
        || manifest.get("gypfile") == Some(&serde_json::Value::Bool(false))
    {
        return None;
    }
    std::fs::symlink_metadata(package_dir.join("binding.gyp"))
        .is_ok_and(|metadata| metadata.is_file())
        .then_some(IMPLIED_INSTALL_SCRIPT)
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
