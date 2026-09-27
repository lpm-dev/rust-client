use super::*;

fn metadata(version: &str, tag: Option<&str>, native_latest: Option<&str>) -> PackageMetadata {
    serde_json::from_value(serde_json::json!({
        "name":"pkg", "dist-tags":tag.map_or_else(|| serde_json::json!({}), |tag| serde_json::json!({"latest":tag})),
        "latestVersion":native_latest, "versions":{version:{"name":"pkg","version":version}}
    })).unwrap()
}

#[test]
fn untagged_batch_versions_do_not_become_advertised_hints() {
    let mut merged = metadata("1.0.0", None, None);
    merge_batch_package_metadata(&mut merged, metadata("3.0.0", None, None));
    assert_eq!(merged.latest_version_tag(), Some("3.0.0"));
    assert_eq!(merged.latest_version_hint(), None);
    assert_eq!(merged.clone().latest_version_hint(), None);
}

#[test]
fn batch_hint_retains_explicit_tags_and_native_latest_values() {
    for (tag, native) in [
        (Some("2.0.0"), None),
        (Some("2.0.0-beta.1"), None),
        (None, Some("2.0.0")),
    ] {
        let mut merged = metadata("1.0.0", tag, native);
        merge_batch_package_metadata(&mut merged, metadata("3.0.0", None, None));
        assert_eq!(merged.latest_version_tag(), Some("3.0.0"));
        assert_eq!(merged.latest_version_hint(), tag.or(native));
        assert_eq!(merged.clone().latest_version_hint(), tag.or(native));
    }
}

#[test]
fn last_advertised_batch_tag_wins_hint_without_changing_selection() {
    let mut merged = metadata("5.0.0", Some("5.0.0"), None);
    merge_batch_package_metadata(&mut merged, metadata("4.0.0", Some("4.0.0"), None));
    assert_eq!(merged.latest_version_tag(), Some("5.0.0"));
    assert_eq!(merged.latest_version_hint(), Some("4.0.0"));
    merge_batch_package_metadata(&mut merged, metadata("6.0.0", None, None));
    assert_eq!(merged.latest_version_tag(), Some("6.0.0"));
    assert_eq!(merged.latest_version_hint(), Some("4.0.0"));
}
