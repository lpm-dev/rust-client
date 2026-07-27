//! Compares the shipped behavioral scan with an exact-semantics candidate.
//!
//! Run with:
//! `cargo run --release -p lpm-security --example behavioral_hotpath`

use std::time::{Duration, Instant};

use lpm_security::behavioral::supply_chain;
use regex::{Regex, RegexSet};

const SUPPLY_PATTERNS: &[&str] = &[
    r"\\x[0-9a-fA-F]{2}",
    r"\b_0x[0-9a-f]{4,}\b",
    r"String\.fromCharCode\s*\(",
    r#"Buffer\.from\s*\([^)]*["']base64["']"#,
    r#"["'](?:@?segment(?:/analytics-node)?|analytics-node)["']"#,
    r#"["']mixpanel["']"#,
    r#"["']posthog-node["']"#,
    r#"["'](?:@amplitude/node|amplitude)["']"#,
    r#"["']keen-tracking["']"#,
    r#"["']countly-sdk-nodejs["']"#,
    r"\bnavigator\.sendBeacon\s*\(",
    r#"\bnew\s+Image\s*\(\s*\)\s*\.src\s*=\s*["']https?://"#,
    r"(?:Intl\.DateTimeFormat|resolvedOptions\(\)\.(?:timeZone|locale)|os\.networkInterfaces)[\s\S]{0,200}process\.exit",
    r"process\.exit[\s\S]{0,200}(?:Intl\.DateTimeFormat|resolvedOptions\(\)\.(?:timeZone|locale)|os\.networkInterfaces)",
    r"for\s*\(\s*let\s+\w+\s*=.*Infinity",
    r"while\s*\(\s*true\s*\)[\s\S]{0,50}replace",
];

fn synthetic_non_ascii_bundle() -> String {
    let line = "const résumé = 'λ'; function ordinary(value) { return value + 1; }\n";
    line.repeat((4 * 1024 * 1024 / line.len()).max(1))
}

fn measure(mut work: impl FnMut()) -> Duration {
    work();
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        work();
        best = best.min(start.elapsed());
    }
    best
}

fn main() {
    let corpus = [
        synthetic_non_ascii_bundle(),
        "const value = _0x1a2b; navigator.sendBeacon('/metrics', value);".repeat(2_000),
        "éfetch(); const _0x1234 = ['a','b']; _0x1234(0x1);".repeat(2_000),
        "while (true) { value = value.replace('a', 'b') }".repeat(2_000),
    ];
    let set = RegexSet::new(SUPPLY_PATTERNS).expect("supply patterns compile");
    let individual: Vec<Regex> = SUPPLY_PATTERNS
        .iter()
        .map(|pattern| Regex::new(pattern).expect("supply pattern compiles"))
        .collect();

    for text in &corpus {
        let set_matches = set.matches(text);
        let individual_matches: Vec<bool> = individual
            .iter()
            .map(|regex| regex.is_match(text))
            .collect();
        let set_matches: Vec<bool> = (0..SUPPLY_PATTERNS.len())
            .map(|index| set_matches.matched(index))
            .collect();
        assert_eq!(set_matches, individual_matches);
    }

    let set_elapsed = measure(|| {
        for text in &corpus {
            std::hint::black_box(set.matches(text));
        }
    });
    let individual_elapsed = measure(|| {
        for text in &corpus {
            for regex in &individual {
                std::hint::black_box(regex.is_match(text));
            }
        }
    });
    let pipeline_elapsed = measure(|| {
        for text in &corpus {
            std::hint::black_box(supply_chain::analyze_supply_chain(text, text.as_bytes()));
        }
    });
    let mib = corpus.iter().map(String::len).sum::<usize>() as f64 / 1_048_576.0;

    println!("corpus={mib:.1}MiB files={}", corpus.len());
    println!(
        "unicode RegexSet={:.2}ms ({:.1}MiB/s)",
        set_elapsed.as_secs_f64() * 1_000.0,
        mib / set_elapsed.as_secs_f64()
    );
    println!(
        "unicode individual={:.2}ms ({:.1}MiB/s)",
        individual_elapsed.as_secs_f64() * 1_000.0,
        mib / individual_elapsed.as_secs_f64()
    );
    println!(
        "shipped pipeline={:.2}ms ({:.1}MiB/s)",
        pipeline_elapsed.as_secs_f64() * 1_000.0,
        mib / pipeline_elapsed.as_secs_f64()
    );
}
