use std::path::{Path, PathBuf};

const LINUX: &str = r#"cfg(target_os = "linux")"#;
const MACOS: &str = r#"cfg(target_os = "macos")"#;
const WINDOWS: &str = "cfg(windows)";
const WINDOWS_TARGET_OS: &str = r#"cfg(target_os = "windows")"#;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("integration crate must be under tests/integration")
        .to_path_buf()
}

fn keyring_features(manifest_path: &str, target: &str) -> Vec<String> {
    let path = repo_root().join(manifest_path);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let manifest = content
        .parse::<toml::Value>()
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    manifest
        .get("target")
        .and_then(|targets| targets.get(target))
        .and_then(|target| target.get("dependencies"))
        .and_then(|dependencies| dependencies.get("keyring"))
        .and_then(|keyring| keyring.get("features"))
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| {
            panic!("{manifest_path} must configure keyring features for target {target}")
        })
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .unwrap_or_else(|| panic!("non-string keyring feature in {manifest_path}"))
                .to_owned()
        })
        .collect()
}

#[test]
fn credential_crates_enable_persistent_keyring_backends_for_supported_operating_systems() {
    let expected = [
        (
            "crates/lpm-auth/Cargo.toml",
            LINUX,
            &["linux-native-sync-persistent", "crypto-rust"][..],
        ),
        ("crates/lpm-auth/Cargo.toml", MACOS, &["apple-native"][..]),
        (
            "crates/lpm-auth/Cargo.toml",
            WINDOWS,
            &["windows-native"][..],
        ),
        (
            "crates/lpm-vault/Cargo.toml",
            LINUX,
            &["linux-native-sync-persistent", "crypto-rust"][..],
        ),
        ("crates/lpm-vault/Cargo.toml", MACOS, &["apple-native"][..]),
        (
            "crates/lpm-vault/Cargo.toml",
            WINDOWS_TARGET_OS,
            &["windows-native"][..],
        ),
        (
            "crates/lpm-cli/Cargo.toml",
            LINUX,
            &["linux-native-sync-persistent", "crypto-rust"][..],
        ),
        ("crates/lpm-cli/Cargo.toml", MACOS, &["apple-native"][..]),
        (
            "crates/lpm-cli/Cargo.toml",
            WINDOWS,
            &["windows-native"][..],
        ),
    ];

    for (manifest, target, required_features) in expected {
        let actual = keyring_features(manifest, target);
        for required in required_features {
            assert!(
                actual.iter().any(|feature| feature == required),
                "{manifest} keyring features for {target} must include {required}; found {actual:?}"
            );
        }
    }
}
