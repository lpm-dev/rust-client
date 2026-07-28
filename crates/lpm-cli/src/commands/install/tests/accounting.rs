use super::*;

fn accounting_package(
    name: &str,
    version: &str,
    is_direct: bool,
    is_lpm: bool,
    dependencies: &[(&str, &str)],
) -> InstallPackage {
    let mut package = fake_pkg(name, version, is_direct);
    package.is_lpm = is_lpm;
    package.dependencies = dependencies
        .iter()
        .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
        .collect();
    package
}

fn root_names(packages: &[InstallPackage]) -> Vec<String> {
    select_pool_install_roots(packages)
        .into_iter()
        .map(|root| format!("{}@{}", root.name, root.version))
        .collect()
}

#[test]
fn direct_lpm_package_is_an_accounting_root() {
    let alpha = accounting_package("@lpm.dev/alice.alpha", "1.0.0", true, true, &[]);

    assert_eq!(root_names(&[alpha]), vec!["@lpm.dev/alice.alpha@1.0.0"]);
}

#[test]
fn lpm_descendant_below_direct_lpm_root_is_not_an_additional_root() {
    let alpha = accounting_package(
        "@lpm.dev/alice.alpha",
        "1.0.0",
        true,
        true,
        &[("npm-x", "1.0.0")],
    );
    let npm_x = accounting_package(
        "npm-x",
        "1.0.0",
        false,
        false,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(
        root_names(&[beta, npm_x, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0"]
    );
}

#[test]
fn lpm_descendant_below_only_npm_ancestors_is_an_accounting_root() {
    let npm_x = accounting_package(
        "npm-x",
        "1.0.0",
        true,
        false,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(root_names(&[beta, npm_x]), vec!["@lpm.dev/bob.beta@2.0.0"]);
}

#[test]
fn multiple_direct_roots_are_sorted_and_deduplicated() {
    let charlie = accounting_package("@lpm.dev/carol.charlie", "3.0.0", true, true, &[]);
    let alpha = accounting_package("@lpm.dev/alice.alpha", "1.0.0", true, true, &[]);
    let alpha_duplicate = accounting_package("@lpm.dev/alice.alpha", "1.0.0", true, true, &[]);

    assert_eq!(
        root_names(&[charlie, alpha_duplicate, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0", "@lpm.dev/carol.charlie@3.0.0",]
    );
}

#[test]
fn direct_lpm_root_remains_separate_when_also_covered_by_an_lpm_ancestor() {
    let alpha = accounting_package(
        "@lpm.dev/alice.alpha",
        "1.0.0",
        true,
        true,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", true, true, &[]);

    assert_eq!(
        root_names(&[beta, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0", "@lpm.dev/bob.beta@2.0.0",]
    );
}

#[test]
fn lpm_descendant_reached_through_npm_is_not_promoted_when_an_lpm_root_also_covers_it() {
    let alpha = accounting_package(
        "@lpm.dev/alice.alpha",
        "1.0.0",
        true,
        true,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let npm_x = accounting_package(
        "npm-x",
        "1.0.0",
        true,
        false,
        &[("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(
        root_names(&[npm_x, beta, alpha]),
        vec!["@lpm.dev/alice.alpha@1.0.0"]
    );
}

#[test]
fn npm_cycles_are_bounded_while_discovering_lpm_roots() {
    let npm_x = accounting_package("npm-x", "1.0.0", true, false, &[("npm-y", "1.0.0")]);
    let npm_y = accounting_package(
        "npm-y",
        "1.0.0",
        false,
        false,
        &[("npm-x", "1.0.0"), ("@lpm.dev/bob.beta", "2.0.0")],
    );
    let beta = accounting_package("@lpm.dev/bob.beta", "2.0.0", false, true, &[]);

    assert_eq!(
        root_names(&[npm_y, beta, npm_x]),
        vec!["@lpm.dev/bob.beta@2.0.0"]
    );
}
