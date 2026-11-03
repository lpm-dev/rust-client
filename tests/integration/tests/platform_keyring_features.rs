//! Credentials must reach the operating system's persistent store on every
//! supported platform. A crate that reached a keyring crate without a
//! platform store would keep credentials in memory, losing them at exit.

use std::path::{Path, PathBuf};

const LINUX: &str = r#"cfg(target_os = "linux")"#;
const MACOS: &str = r#"cfg(target_os = "macos")"#;
const WINDOWS: &str = "cfg(windows)";

const CREDENTIAL_CRATES: [&str; 3] = [
    "crates/lpm-auth/Cargo.toml",
    "crates/lpm-vault/Cargo.toml",
    "crates/lpm-cli/Cargo.toml",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("integration crate must be under tests/integration")
        .to_path_buf()
}

fn manifest(path: &str) -> toml::Value {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&content)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The `dependencies` tables a manifest builds with: its own and each
/// target's, labeled by where they are.
fn dependency_tables(manifest: &toml::Value) -> Vec<(String, &toml::Table)> {
    let mut tables = Vec::new();
    if let Some(dependencies) = manifest.get("dependencies").and_then(toml::Value::as_table) {
        tables.push(("dependencies".to_string(), dependencies));
    }
    for (target, table) in manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
    {
        if let Some(dependencies) = table.get("dependencies").and_then(toml::Value::as_table) {
            tables.push((format!("target {target}"), dependencies));
        }
    }
    tables
}

#[test]
fn lpm_keyring_uses_each_supported_operating_systems_persistent_store() {
    let manifest = manifest("crates/lpm-keyring/Cargo.toml");
    let expected = [
        (MACOS, "apple-native-keyring-store", &["keychain"][..]),
        (WINDOWS, "windows-native-keyring-store", &[][..]),
        (
            LINUX,
            "dbus-secret-service-keyring-store",
            &["crypto-rust"][..],
        ),
    ];

    for (target, store, required_features) in expected {
        let dependency = manifest
            .get("target")
            .and_then(|targets| targets.get(target))
            .and_then(|target| target.get("dependencies"))
            .and_then(|dependencies| dependencies.get(store))
            .unwrap_or_else(|| panic!("lpm-keyring must depend on {store} for {target}"));
        let features = dependency
            .get("features")
            .and_then(toml::Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for required in required_features {
            assert!(
                features.contains(required),
                "lpm-keyring's {store} for {target} must enable {required}; found {features:?}"
            );
        }
    }
}

#[test]
fn credential_crates_reach_the_store_only_through_lpm_keyring() {
    for path in CREDENTIAL_CRATES {
        let manifest = manifest(path);
        let tables = dependency_tables(&manifest);

        assert!(
            tables
                .iter()
                .any(|(name, table)| name == "dependencies" && table.contains_key("lpm-keyring")),
            "{path} must depend on lpm-keyring"
        );
        for (name, table) in &tables {
            for direct in ["keyring", "keyring-core"] {
                assert!(
                    !table.contains_key(direct),
                    "{path} {name} must reach the credential store through lpm-keyring, not {direct}"
                );
            }
        }
    }
}
