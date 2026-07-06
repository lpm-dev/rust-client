use super::super::parity::compare_package_parity_with_baseline;
use super::common::{
    fake_package, info_with_versions, package_set_for_completion_order, resolve_request_for_test,
};
use std::sync::Arc;

#[test]
fn package_parity_reports_extra_and_missing_packages() {
    let candidate = vec![
        fake_package("shared", "1.0.0", &[]),
        fake_package("candidate-only", "1.0.0", &[]),
    ];
    let baseline = vec![
        fake_package("shared", "1.0.0", &[]),
        fake_package("baseline-only", "1.0.0", &[]),
    ];

    let parity = compare_package_parity_with_baseline(&candidate, &baseline, "install-packages");

    assert!(!parity.matches);
    assert_eq!(parity.candidate_count, 2);
    assert_eq!(parity.baseline_count, 2);
    assert_eq!(parity.count_delta, 0);
    assert_eq!(parity.extra_count, 1);
    assert_eq!(parity.missing_count, 1);
    assert!(parity.extra[0].contains("candidate-only@1.0.0"));
    assert!(parity.missing[0].contains("baseline-only@1.0.0"));
}

#[test]
fn package_parity_reports_dependency_fingerprint_mismatch() {
    let candidate = vec![fake_package("shared", "1.0.0", &[("left", "1.0.0")])];
    let baseline = vec![fake_package("shared", "1.0.0", &[("right", "1.0.0")])];

    let parity = compare_package_parity_with_baseline(&candidate, &baseline, "install-packages");

    assert!(!parity.matches);
    assert_eq!(parity.extra_count, 0);
    assert_eq!(parity.missing_count, 0);
    assert_eq!(parity.fingerprint_mismatch_count, 1);
    assert_eq!(
        parity.fingerprint_mismatches[0].candidate.dependencies,
        vec![("left".to_string(), "1.0.0".to_string())]
    );
    assert_eq!(
        parity.fingerprint_mismatches[0].baseline.dependencies,
        vec![("right".to_string(), "1.0.0".to_string())]
    );
}

#[test]
fn package_parity_catches_completion_order_dependent_reuse() {
    let info = Arc::new(info_with_versions(&["1.9.0", "1.0.5", "1.0.0"]));
    let narrow = resolve_request_for_test(
        "shared",
        "~1.0.0",
        Some(("narrow-parent".to_string(), "1.0.0".to_string())),
        false,
        false,
    );
    let broad = resolve_request_for_test(
        "shared",
        "^1.0.0",
        Some(("broad-parent".to_string(), "1.0.0".to_string())),
        false,
        false,
    );

    let narrow_first =
        package_set_for_completion_order(vec![narrow.clone(), broad.clone()], Arc::clone(&info));
    let broad_first = package_set_for_completion_order(vec![broad, narrow], info);

    let parity =
        compare_package_parity_with_baseline(&narrow_first, &broad_first, "completion-order");

    assert!(!parity.matches);
    assert_eq!(parity.candidate_count, 1);
    assert_eq!(parity.baseline_count, 2);
    assert_eq!(parity.missing_count, 1);
    assert!(parity.missing[0].contains("shared@1.9.0"));
}
