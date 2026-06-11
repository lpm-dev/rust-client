use lpm_semver::{Version, VersionReq};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RangeCorpus {
    source_file: String,
    cases: Vec<RangeCase>,
    skipped: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RangeCase {
    source_index: usize,
    range: String,
    version: String,
    expected: bool,
}

#[derive(Debug, Deserialize)]
struct ComparisonCorpus {
    source_file: String,
    cases: Vec<ComparisonCase>,
    skipped: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ComparisonCase {
    source_index: usize,
    greater: String,
    less: String,
}

fn range_corpus(json: &str) -> RangeCorpus {
    serde_json::from_str(json).expect("node-semver range fixture must decode")
}

fn comparison_corpus(json: &str) -> ComparisonCorpus {
    serde_json::from_str(json).expect("node-semver comparison fixture must decode")
}

#[test]
fn node_semver_range_include_corpus_matches_lpm_behavior() {
    let corpus = range_corpus(include_str!("fixtures/node-semver/range_include.json"));
    assert_eq!(corpus.source_file, "test/fixtures/range-include.js");
    assert!(
        corpus.cases.len() >= 90,
        "fixture refresh unexpectedly reduced executable include corpus to {} cases",
        corpus.cases.len()
    );
    assert!(
        !corpus.skipped.is_empty(),
        "upstream option-only rows should remain visible as skipped fixture data"
    );

    for case in corpus.cases {
        assert_range_match(&case);
    }
}

#[test]
fn node_semver_range_exclude_corpus_matches_lpm_behavior() {
    let corpus = range_corpus(include_str!("fixtures/node-semver/range_exclude.json"));
    assert_eq!(corpus.source_file, "test/fixtures/range-exclude.js");
    assert!(
        corpus.cases.len() >= 70,
        "fixture refresh unexpectedly reduced executable exclude corpus to {} cases",
        corpus.cases.len()
    );
    assert!(
        !corpus.skipped.is_empty(),
        "upstream option-only rows should remain visible as skipped fixture data"
    );

    for case in corpus.cases {
        assert_range_match(&case);
    }
}

#[test]
fn node_semver_comparison_corpus_matches_lpm_ordering() {
    let corpus = comparison_corpus(include_str!("fixtures/node-semver/comparisons.json"));
    assert_eq!(corpus.source_file, "test/fixtures/comparisons.js");
    assert!(
        corpus.cases.len() >= 15,
        "fixture refresh unexpectedly reduced executable comparison corpus to {} cases",
        corpus.cases.len()
    );
    assert!(
        !corpus.skipped.is_empty(),
        "upstream loose-option rows should remain visible as skipped fixture data"
    );

    for case in corpus.cases {
        let greater = Version::parse(&case.greater).unwrap_or_else(|error| {
            panic!(
                "{} #{} greater version {:?} should parse: {error}",
                corpus.source_file, case.source_index, case.greater
            )
        });
        let less = Version::parse(&case.less).unwrap_or_else(|error| {
            panic!(
                "{} #{} lesser version {:?} should parse: {error}",
                corpus.source_file, case.source_index, case.less
            )
        });

        assert!(
            greater > less,
            "{} #{} expected {:?} > {:?}",
            corpus.source_file,
            case.source_index,
            case.greater,
            case.less
        );
        assert_ne!(
            greater, less,
            "{} #{} comparison corpus pair must not be equal",
            corpus.source_file, case.source_index
        );
    }
}

fn assert_range_match(case: &RangeCase) {
    let req = VersionReq::parse(&case.range).unwrap_or_else(|error| {
        panic!(
            "range fixture #{} range {:?} should parse: {error}",
            case.source_index, case.range
        )
    });
    let version = match Version::parse(&case.version) {
        Ok(version) => version,
        Err(error) => {
            assert!(
                !case.expected,
                "range fixture #{} included invalid version {:?}: {error}",
                case.source_index, case.version
            );
            return;
        }
    };

    assert_eq!(
        req.matches(&version),
        case.expected,
        "range fixture #{} expected range {:?} to {} version {:?}",
        case.source_index,
        case.range,
        if case.expected { "include" } else { "exclude" },
        case.version
    );
}
