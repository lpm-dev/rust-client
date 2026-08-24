use super::super::fetch_schedule::{lockfile_fetch_schedule, prioritize_fetch_schedule};
use super::common::fake_package;

#[test]
fn lockfile_fetch_schedule_prioritizes_direct_roots_then_fanout() {
    let mut direct = fake_package("direct-root", "1.0.0", &[]);
    direct.is_direct = true;
    let high_fanout = fake_package(
        "high-fanout",
        "1.0.0",
        &[("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0")],
    );
    let low_fanout = fake_package("low-fanout", "1.0.0", &[("a", "1.0.0")]);

    let scheduled = lockfile_fetch_schedule(&[low_fanout, high_fanout, direct]);
    let names: Vec<_> = scheduled
        .iter()
        .map(|package| package.name.as_str())
        .collect();

    assert_eq!(names, vec!["direct-root", "high-fanout", "low-fanout"]);
}

#[test]
fn production_fetch_schedule_prioritizes_only_the_supplied_remote_misses() {
    let cached_direct = {
        let mut package = fake_package("cached-direct", "1.0.0", &[]);
        package.is_direct = true;
        package
    };
    let mut direct = fake_package("direct-root", "1.0.0", &[("a", "1.0.0")]);
    direct.is_direct = true;
    let transitive = fake_package(
        "transitive",
        "1.0.0",
        &[("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0")],
    );
    let mut remote_misses = vec![transitive, direct];

    prioritize_fetch_schedule(&mut remote_misses);

    let names: Vec<_> = remote_misses
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    assert_eq!(names, vec!["direct-root", "transitive"]);
    assert!(!names.contains(&cached_direct.name.as_str()));
}
