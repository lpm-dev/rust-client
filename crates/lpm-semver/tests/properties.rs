use lpm_semver::{Version, VersionReq, max_satisfying};
use proptest::prelude::*;

fn stable_version_string() -> impl Strategy<Value = String> {
    (0_u64..1_000, 0_u64..1_000, 0_u64..1_000)
        .prop_map(|(major, minor, patch)| format!("{major}.{minor}.{patch}"))
}

fn prerelease_identifier() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("alpha".to_string()),
        Just("beta".to_string()),
        Just("rc".to_string()),
        (0_u32..100).prop_map(|n| n.to_string()),
    ]
}

fn version_string() -> impl Strategy<Value = String> {
    (
        stable_version_string(),
        prop::option::of(prop::collection::vec(prerelease_identifier(), 1..4)),
        prop::option::of(prop::collection::vec(prerelease_identifier(), 1..4)),
    )
        .prop_map(|(base, prerelease, build)| {
            let mut version = String::with_capacity(base.len() + 32);
            version.push_str(&base);
            if let Some(parts) = prerelease {
                version.push('-');
                version.push_str(&parts.join("."));
            }
            if let Some(parts) = build {
                version.push('+');
                version.push_str(&parts.join("."));
            }
            version
        })
}

fn stable_version() -> impl Strategy<Value = Version> {
    stable_version_string().prop_map(|version| Version::parse(&version).unwrap())
}

proptest! {
    #[test]
    fn valid_versions_round_trip_through_display(version in version_string()) {
        let parsed = Version::parse(&version).unwrap();
        let rendered = parsed.to_string();
        let reparsed = Version::parse(&rendered).unwrap();

        prop_assert_eq!(parsed, reparsed);
    }

    #[test]
    fn version_ordering_is_transitive(
        a in stable_version(),
        b in stable_version(),
        c in stable_version(),
    ) {
        if a <= b && b <= c {
            prop_assert!(a <= c);
        }
        if a >= b && b >= c {
            prop_assert!(a >= c);
        }
    }

    #[test]
    fn wildcard_range_matches_stable_versions(version in stable_version()) {
        let range = VersionReq::parse("*").unwrap();

        prop_assert!(range.matches(&version));
    }

    #[test]
    fn exact_stable_range_matches_itself(version in stable_version_string()) {
        let parsed = Version::parse(&version).unwrap();
        let range = VersionReq::parse(&version).unwrap();

        prop_assert!(range.matches(&parsed));
    }

    #[test]
    fn arbitrary_range_input_never_panics(input in ".{0,256}") {
        let _ = VersionReq::parse(&input);
    }

    #[test]
    fn max_satisfying_returns_the_highest_matching_version(
        major in 0_u64..20,
        versions in prop::collection::vec(stable_version(), 0..64),
    ) {
        let range = VersionReq::parse(&format!(">={major}.0.0 <{}.0.0", major + 1)).unwrap();
        let refs: Vec<&Version> = versions.iter().collect();

        let expected = refs
            .iter()
            .copied()
            .filter(|version| range.matches(version))
            .max();
        let actual = max_satisfying(&refs, &range);

        prop_assert_eq!(actual, expected);
    }
}
